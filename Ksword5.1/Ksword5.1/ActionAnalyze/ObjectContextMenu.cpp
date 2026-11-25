#include "ObjectContextMenu.h"

#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncOperation.h"
#include "../UI/ThemedMessageBox.h"
#include "../theme.h"

#include <QApplication>
#include <QClipboard>
#include <QContextMenuEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMenu>
#include <QMessageBox>
#include <QStringList>
#include <QTimer>

namespace ks::action_analyze
{
namespace
{
    using ks::i18n::LanguageManager;

    // 保留可编辑器粘贴的稳定字段名，64 位 ID 和时间以十进制字符串表示。
    QString IdentifierText(const ObjectMenuRef& object)
    {
        const bool thread = object.kind == ObjectMenuKind::Thread; // 稳定引用的对象类别。
        QJsonObject ids{ // 复制仅由所选引用证实的标识。
            {QStringLiteral("project_id"), object.sample.projectId.toString(QUuid::WithoutBraces)},
            {QStringLiteral("sample_id"), object.sample.sampleId.toString(QUuid::WithoutBraces)},
            {QStringLiteral("kind"), thread ? QStringLiteral("thread") : QStringLiteral("process")},
            {QStringLiteral("object_id"), QString::number(object.objectId)}
        };
        return QString::fromUtf8(QJsonDocument(ids).toJson(QJsonDocument::Indented));
    }

    // 未解析的对象始终显示其采样内 ID，避免把事件头 PID／TID 当作对象属性。
    QString ScopeText(const ObjectMenuRef& object)
    {
        const QString label = ks::i18n::sourceText(object.kind == ObjectMenuKind::Thread
            ? QStringLiteral("线程对象 ID") : QStringLiteral("进程对象 ID")); // 使用已有字段译文。
        return label + QStringLiteral(": ") + QString::number(object.objectId);
    }

    // 用数字 ID 和采样内对象 ID 同时显示范围，线程行包含真正的 owner。
    QString ScopeText(const ObjectSelection& subject)
    {
        auto& language = LanguageManager::instance(); // 当前 UI 语言。
        if (subject.thread)
        {
            return language.text(QStringLiteral("action_analyze.object.thread_scope"),
                QStringLiteral("线程 TID %1（对象 %2），所属进程 PID %3（对象 %4）"))
                .arg(subject.thread->tid).arg(subject.thread->objectId).arg(subject.process.pid).arg(subject.process.objectId);
        }
        return language.text(QStringLiteral("action_analyze.object.process_scope"), QStringLiteral("进程 PID %1（对象 %2）"))
            .arg(subject.process.pid).arg(subject.process.objectId);
    }

    // 除实际来源原因外，区分未核验、查无证据、查询错误及当前写入占用。
    QString DiagnosticBlock(const ObjectMenuCapabilities& state, const ObjectMenuRef& object, bool busy)
    {
        auto& language = LanguageManager::instance(); // 当前 UI 语言。
        if (busy)
        {
            return language.text(QStringLiteral("action_analyze.dump.busy"), QStringLiteral("另一项 Dump 导出正在写入。"));
        }
        const QString detail = state.diagnosticReason.isEmpty() ? QString() : u'\n' + state.diagnosticReason; // 补充原始原因。
        switch (state.diagnostic)
        {
        case DiagnosticAvailability::Unresolved:
            return language.text(QStringLiteral("action_analyze.dump.unresolved"), QStringLiteral("此对象的归档诊断证据尚未核验。")) + detail;
        case DiagnosticAvailability::Absent:
            return language.text(QStringLiteral("action_analyze.dump.absent"), QStringLiteral("此对象没有身份匹配的归档诊断证据。")) + detail;
        case DiagnosticAvailability::Failed:
            return language.text(QStringLiteral("action_analyze.dump.lookup_failed"), QStringLiteral("读取此对象的归档证据目录失败。")) + detail;
        case DiagnosticAvailability::Ready:
            if (state.verifiedSubject && object.matches(*state.verifiedSubject) && state.archive
                && MatchesArchivedDiagnostic(*state.verifiedSubject, *state.archive))
            {
                return {};
            }
            return language.text(QStringLiteral("action_analyze.dump.invalid_evidence"), QStringLiteral("归档证据的身份、格式或描述无效。"));
        }
        return {};
    }

    // 只选择实际文件格式，扩展名与可见描述共用此映射。
    QString FormatText(DiagnosticFormat format)
    {
        auto& language = LanguageManager::instance(); // 当前 UI 语言。
        return format == DiagnosticFormat::ProcessMinidump
            ? language.text(QStringLiteral("action_analyze.dump.process_format"), QStringLiteral("Windows 用户态进程 Minidump (*.dmp)"))
            : language.text(QStringLiteral("action_analyze.dump.thread_format"), QStringLiteral("单线程诊断证据 (*.json)"));
    }

    // 写入结果与归档采集完整度独立显示，只有 commit 成功后才报告保存路径。
    QString ResultText(const DiagnosticExportResult& result, const ArchivedDiagnostic& archive, const QString& path)
    {
        auto& language = LanguageManager::instance(); // 当前 UI 语言。
        switch (result.status)
        {
        case DiagnosticExportStatus::Saved:
            return language.text(QStringLiteral("action_analyze.dump.saved"), QStringLiteral("已导出归档证据（%1 字节）。\n%2"))
                .arg(result.bytes).arg(path);
        case DiagnosticExportStatus::SavedPartial:
            return language.text(QStringLiteral("action_analyze.dump.saved_partial"), QStringLiteral("已导出归档中的部分诊断资料（%1 字节）。\n%2\n缺口：%3"))
                .arg(result.bytes).arg(path, archive.limitReason);
        case DiagnosticExportStatus::InvalidEvidence:
            return language.text(QStringLiteral("action_analyze.dump.invalid_evidence"), QStringLiteral("归档证据的身份、格式或描述无效。"));
        case DiagnosticExportStatus::InvalidDestination:
            return language.text(QStringLiteral("action_analyze.dump.invalid_destination"), QStringLiteral("请选择归档目录之外的文件作为导出目标。"));
        case DiagnosticExportStatus::SourceMissing:
            return language.text(QStringLiteral("action_analyze.dump.source_missing"), QStringLiteral("找不到归档中登记的证据文件。"));
        case DiagnosticExportStatus::SourceReadFailed:
            return language.text(QStringLiteral("action_analyze.dump.source_read_failed"), QStringLiteral("无法读取归档证据文件。"));
        case DiagnosticExportStatus::SourceMismatch:
            return language.text(QStringLiteral("action_analyze.dump.source_mismatch"), QStringLiteral("证据文件的字节数、格式或 SHA-256 与归档记录不匹配。"));
        case DiagnosticExportStatus::WriteFailed:
            return language.text(QStringLiteral("action_analyze.dump.write_failed"), QStringLiteral("无法保存证据到所选路径。"));
        case DiagnosticExportStatus::Canceled:
            return {};
        }
        return {};
    }
}

bool ObjectMenuRef::isValid() const
{
    return !sample.projectId.isNull() && !sample.sampleId.isNull() && objectId != 0;
}

bool ObjectMenuRef::matches(const ObjectSelection& subject) const
{
    if (!subject.isValid() || sample != subject.sample)
    {
        return false;
    }
    return kind == ObjectMenuKind::Thread ? (subject.thread && subject.thread->objectId == objectId)
        : (!subject.thread && subject.process.objectId == objectId);
}

ObjectContextMenu::ObjectContextMenu(QWidget* owner, ObjectMenuCallbacks callbacks)
    : QObject(owner), m_owner(owner), m_callbacks(std::move(callbacks)), m_export(new ks::ui::AsyncOperation(this))
{
}

ObjectContextMenu::~ObjectContextMenu()
{
    m_export->close();
    if (m_menu)
    {
        m_menu->close();
    }
}

ObjectMenuCapabilities ObjectContextMenu::capabilities(const ObjectMenuRef& object) const
{
    // 先查证据及页面能力，再复核对应消费者是否存在。
    auto state = m_callbacks.capabilities ? m_callbacks.capabilities(object) : ObjectMenuCapabilities{}; // 本次能力回读。
    state.viewEvidence.available = state.viewEvidence.available && bool(m_callbacks.viewEvidence);
    state.filterByObject.available = state.filterByObject.available && bool(m_callbacks.filterByObject);
    return state;
}

bool ObjectContextMenu::handleContextMenu(QContextMenuEvent& event, QWidget* source, const ObjectPicker& pickAt,
    std::optional<ObjectMenuRef> keyboardObject, const QPoint& keyboardAnchor)
{
    if (!source)
    {
        return false;
    }
    const bool keyboard = event.reason() == QContextMenuEvent::Keyboard; // 菜单键或 Shift+F10 从当前对象打开。
    const auto subject = keyboard ? std::move(keyboardObject) : (pickAt ? pickAt(event.pos()) : std::nullopt); // 不替换选区。
    const QPoint position = keyboard ? source->mapToGlobal(keyboardAnchor) : event.globalPos(); // 原生菜单位置。
    if (subject && popup(position, *subject))
    {
        event.accept();
        return true;
    }
    return false;
}

bool ObjectContextMenu::popup(const QPoint& globalPosition, ObjectMenuRef object)
{
    if (!m_owner || !object.isValid())
    {
        return false;
    }
    if (m_menu)
    {
        m_menu->close();
    }

    const auto state = capabilities(object); // 仅查已发布快照。
    const QString diagnosticBlock = DiagnosticBlock(state, object, m_export->isBusy()); // 状态可由键盘读取。
    auto& language = LanguageManager::instance(); // 打开时按当前语言和主题构建。
    auto* menu = new QMenu(m_owner); // 采用共享不透明菜单及 Qt 原生选择行为。
    m_menu = menu;
    menu->setStyleSheet(KswordTheme::ContextMenuStyle());
    connect(menu, &QMenu::aboutToHide, menu, &QObject::deleteLater);

    // 允许原生菜单先关闭，再执行回调。动作承接本次冻结的选择和可保存文件。
    const auto addAction = [this, menu, object, archive = state.archive](Action id, const QString& text, bool available) {
        auto* action = menu->addAction(text); // 菜单项由 QMenu 持有。
        action->setEnabled(available);
        connect(action, &QAction::triggered, this, [this, id, object, archive]() {
            QTimer::singleShot(0, this, [this, id, object, archive]() { dispatch(id, object, archive); });
        });
    };
    menu->addAction(state.verifiedSubject && object.matches(*state.verifiedSubject)
        ? ScopeText(*state.verifiedSubject) : ScopeText(object))->setEnabled(false);
    menu->addSeparator();
    addAction(Action::View, language.text(QStringLiteral("action_analyze.object.view"), QStringLiteral("查看对象证据")), state.viewEvidence.available);
    addAction(Action::Filter, language.text(QStringLiteral("action_analyze.object.filter"), QStringLiteral("按此对象筛选")), state.filterByObject.available);
    addAction(Action::Copy, language.text(QStringLiteral("action_analyze.object.copy"), QStringLiteral("复制对象标识")), true);
    menu->addSeparator();
    addAction(Action::Export, language.text(QStringLiteral("action_analyze.dump.export"), QStringLiteral("导出 Dump…")), diagnosticBlock.isEmpty());
    if (!diagnosticBlock.isEmpty() || !state.viewEvidence.available || !state.filterByObject.available)
    {
        addAction(Action::Explain, language.text(QStringLiteral("action_analyze.object.action_status"), QStringLiteral("查看操作状态")), true);
    }
    menu->popup(globalPosition);
    return true;
}

void ObjectContextMenu::dispatch(Action action, const ObjectMenuRef& object, const std::optional<ArchivedDiagnostic>& offeredArchive)
{
    if (action == Action::Copy)
    {
        QApplication::clipboard()->setText(IdentifierText(object));
        return;
    }

    const auto state = capabilities(object); // 刷新、换样本后仍只查询捕获的对象。
    auto& language = LanguageManager::instance(); // 当前 UI 语言。
    if (action == Action::View && state.viewEvidence.available)
    {
        m_callbacks.viewEvidence(object);
        return;
    }
    if (action == Action::Filter && state.filterByObject.available)
    {
        m_callbacks.filterByObject(object);
        return;
    }

    const QString diagnosticBlock = DiagnosticBlock(state, object, m_export->isBusy()); // 以动作触发时能力为准。
    if (action == Action::Export && diagnosticBlock.isEmpty() && offeredArchive && offeredArchive == state.archive)
    {
        chooseExport(object, *offeredArchive);
        return;
    }

    QStringList lines{ScopeText(object), object.sample.sampleId.toString(QUuid::WithoutBraces)}; // 说明所属对象及采样。
    if ((action == Action::View || action == Action::Explain) && !state.viewEvidence.available)
    {
        lines << (state.viewEvidence.reason.isEmpty() ? language.text(QStringLiteral("action_analyze.object.view_unavailable"),
            QStringLiteral("当前视图无法打开此对象的证据详情。")) : state.viewEvidence.reason);
    }
    if ((action == Action::Filter || action == Action::Explain) && !state.filterByObject.available)
    {
        lines << (state.filterByObject.reason.isEmpty() ? language.text(QStringLiteral("action_analyze.object.filter_unavailable"),
            QStringLiteral("当前视图无法按此对象筛选。")) : state.filterByObject.reason);
    }
    if (action == Action::Export || action == Action::Explain)
    {
        lines << (!diagnosticBlock.isEmpty() ? diagnosticBlock : action == Action::Export
            ? language.text(QStringLiteral("action_analyze.dump.changed"), QStringLiteral("归档证据已变化，请重新打开对象菜单。"))
            : FormatText(state.archive->format));
    }
    ks::ui::OpenThemedTextMessage(m_owner, QMessageBox::Information,
        language.text(QStringLiteral("action_analyze.object.action_status"), QStringLiteral("查看操作状态")), lines.join(u'\n'));
}

void ObjectContextMenu::chooseExport(const ObjectMenuRef& object, const ArchivedDiagnostic& offeredArchive)
{
    auto& language = LanguageManager::instance(); // 当前 UI 语言。
    const QPointer<ObjectContextMenu> guard(this); // 系统文件对话框期间工作台可关闭。
    const auto& subject = offeredArchive.subject; // 上一步已核对的导出对象与所属进程。
    const bool thread = subject.thread.has_value(); // 线程资料独立使用 JSON 格式。
    const QString suffix = thread ? QStringLiteral("json") : QStringLiteral("dmp"); // 已验证真实格式。
    const QString slug = thread ? QStringLiteral("thread") : QStringLiteral("process"); // 文件名的固定对象类别。
    const auto nativeId = thread ? subject.thread->tid : subject.process.pid; // 文件名中的原生 ID。
    const QString defaultName = slug + u'-' + QString::number(nativeId) + u'.' + suffix; // 建议的文件名。
    const QString title = language.text(QStringLiteral("action_analyze.dump.export"), QStringLiteral("导出 Dump…")); // 保存与回执标题。
    const QString scope = ScopeText(subject) + u'\n' + subject.sample.sampleId.toString(QUuid::WithoutBraces)
        + u'\n' + FormatText(offeredArchive.format); // 回执同时包含采样、作用域和格式。
    const QString path = QFileDialog::getSaveFileName(m_owner, title + QStringLiteral(" — ") + ScopeText(subject),
        defaultName, FormatText(offeredArchive.format)); // 仅用户选择后返回实际文件路径。
    if (!guard || path.isEmpty())
    {
        return;
    }

    // 不隐式改写文件名，避免扩展名变化绕过文件选择器的覆盖确认。
    if (QFileInfo(path).suffix().compare(suffix, Qt::CaseInsensitive) != 0)
    {
        ks::ui::OpenThemedTextMessage(m_owner, QMessageBox::Warning, title, language.text(QStringLiteral("action_analyze.dump.extension"),
            QStringLiteral("文件名必须使用 .%1 扩展名。请再次选择保存路径。")).arg(suffix));
        return;
    }
    const auto state = capabilities(object); // 保存选择期间可能关闭或更换归档。
    const QString block = DiagnosticBlock(state, object, m_export->isBusy()); // 执行前记录真实不可用原因。
    if (!block.isEmpty() || offeredArchive != state.archive)
    {
        ks::ui::OpenThemedTextMessage(m_owner, QMessageBox::Warning, title, block.isEmpty() ? language.text(QStringLiteral("action_analyze.dump.changed"),
            QStringLiteral("归档证据已变化，请重新打开对象菜单。")) : block);
        return;
    }

    // 文件写入使用共享异步事务，阶段切页不会把结果改挂到其他对象。
    const auto ticket = m_export->submitTransaction<ArchivedDiagnostic, DiagnosticExportResult>(offeredArchive,
        [subject, path](const ArchivedDiagnostic& archive) { return ExportArchivedDiagnostic(subject, archive, path); },
        [this, offeredArchive, title, scope, path](const DiagnosticExportResult& result, std::uint64_t) {
            const QString message = ResultText(result, offeredArchive, path); // 按真实终态展示。
            if (!message.isEmpty())
            {
                const bool saved = result.status == DiagnosticExportStatus::Saved || result.status == DiagnosticExportStatus::SavedPartial;
                ks::ui::OpenThemedTextMessage(m_owner, saved ? QMessageBox::Information : QMessageBox::Warning, title,
                    scope + u'\n' + message + (result.detail.isEmpty() ? QString() : u'\n' + result.detail));
            }
            return true;
        },
        [this, title, scope](std::exception_ptr) {
            ks::ui::OpenThemedTextMessage(m_owner, QMessageBox::Warning, title,
                scope + u'\n' + LanguageManager::instance().text(QStringLiteral("action_analyze.dump.write_failed"),
                    QStringLiteral("无法保存证据到所选路径。")));
        });
    if (!ticket && guard)
    {
        ks::ui::OpenThemedTextMessage(m_owner, QMessageBox::Warning, title, language.text(QStringLiteral("action_analyze.dump.not_started"),
            QStringLiteral("未开始导出，请重新打开对象菜单。")));
    }
}
}
