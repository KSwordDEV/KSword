#include "MemoryWorkbenchView.h"
#include "../SecondaryPageLayout.h"
#include "AddressBookPanel.h"
#include "WorkbenchShared.h"
#include "WorkbenchStatusBar.h"
#include "WorkbenchWriteController.h"
#include "../../MemoryDock/WorkbenchPointerChainAccess.h"
#include "../../Internationalization/LanguageManager.h"
#include "../../theme.h"
#include <QApplication>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileInfo>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include "../StructuredFieldView.h"
#include <QStackedWidget>
#include <QThreadPool>
#include <QVBoxLayout>

namespace ks::ui
{
    namespace
    {
        QString T(const QString& source) { return ks::i18n::sourceText(source); }

        QString Offset(const std::int64_t offset)
        {
            const auto magnitude = offset < 0 ? static_cast<std::uint64_t>(-(offset + 1)) + 1U
                : static_cast<std::uint64_t>(offset);
            return (offset < 0 ? QStringLiteral("-0x") : QStringLiteral("0x"))
                + QString::number(static_cast<qulonglong>(magnitude), 16).toUpper();
        }

        QString IssueText(const ksword::memwb_pointer_access::Issue issue)
        {
            using I = ksword::memwb_pointer_access::Issue;
            switch (issue)
            {
            case I::None: return {};
            case I::InvalidTarget: return T(QStringLiteral("指针链只支持有效的进程目标。"));
            case I::UnsupportedChannel: return T(QStringLiteral("当前工作台的 DDMA 通道不支持指针链解引用。"));
            case I::IdentityUnavailable: return T(QStringLiteral("无法核对进程实例或位数，指针链未解析。"));
            case I::TargetChanged: return T(QStringLiteral("进程实例已改变，请重新选择目标。"));
            case I::ModuleUnavailable: return T(QStringLiteral("基址模块不可用或存在歧义，请刷新模块列表。"));
            case I::ModuleChanged: return T(QStringLiteral("基址模块的文件或位数已改变，请重新编辑指针链。"));
            case I::WrongProgram: return T(QStringLiteral("该指针链书签绑定的程序与当前目标不一致。"));
            case I::InvalidRoot: return T(QStringLiteral("根指针偏移或链定义无效。"));
            case I::RootRemapped: return T(QStringLiteral("根指针所在模块的映射已改变。"));
            case I::Cancelled: return T(QStringLiteral("指针链解析已取消或超时。"));
            case I::ReadFailed: return T(QStringLiteral("指针链读取失败或读取不完整。"));
            }
            return {};
        }

        FieldDocument BuildPointerTrace(const ksword::memwb_pointer_access::Resolution& resolved)
        {
            FieldDocument document;
            for (std::size_t i = 0; i < resolved.result.steps.size(); ++i)
            {
                const auto& step = resolved.result.steps[i];
                document.section(QStringLiteral("第 %1 级").arg(static_cast<qulonglong>(i + 1)));
                document.field(QStringLiteral("读取地址"), QStringLiteral("0x%1").arg(QString::number(step.readAddress, 16)));
                document.field(QStringLiteral("指针值"), QStringLiteral("0x%1").arg(QString::number(step.pointerValue, 16)));
                document.field(QStringLiteral("偏移"), Offset(step.offset));
                document.field(QStringLiteral("解析地址"), QStringLiteral("0x%1").arg(QString::number(step.resolvedAddress, 16)));
            }
            document.section(QStringLiteral("解析结果"));
            document.field(QStringLiteral("状态码"), QString::number(static_cast<int>(resolved.result.status)));
            if (resolved.result.ok())
                document.field(QStringLiteral("目标地址"), QStringLiteral("0x%1").arg(QString::number(resolved.result.address, 16)));
            else
            {
                using S = ksword::pointer_chain::Status;
                QString detail = IssueText(resolved.issue);
                if (resolved.result.status == S::NullPointer) detail = T(QStringLiteral("遇到空指针。"));
                if (resolved.result.status == S::CycleDetected) detail = T(QStringLiteral("指针链重复访问同一地址。"));
                if (resolved.result.status == S::AddressOverflow) detail = T(QStringLiteral("指针地址或偏移越界。"));
                document.field(QStringLiteral("失败级别"), QString::number(resolved.result.failedLevel + 1));
                document.field(QStringLiteral("原因"), detail);
            }
            if (!resolved.annotation.empty()) document.note(QString::fromUtf8(resolved.annotation.c_str()));
            return document;
        }

        bool SameDefinition(const ksword::memwb::AddressEntry& a, const ksword::memwb::AddressEntry& b)
        {
            return a.id == b.id && a.moduleName == b.moduleName && a.rva == b.rva
                && a.targetKey == b.targetKey && a.pointerChain == b.pointerChain;
        }

        bool SameProgram(const std::string& left, const std::string& right)
        {
            auto a = QString::fromUtf8(left.c_str());
            auto b = QString::fromUtf8(right.c_str());
            a.replace(QLatin1Char('/'), QLatin1Char('\\'));
            b.replace(QLatin1Char('/'), QLatin1Char('\\'));
            return a.compare(b, Qt::CaseInsensitive) == 0;
        }
    }

    void MemoryWorkbenchView::cancelPointerChainResolution()
    {
        ++pointerTicket_;
        if (pointerCancel_) pointerCancel_->store(true);
        if (pointerResolutionBusy_ && statusBar_)
            statusBar_->setDiagnosticsText(T(QStringLiteral("指针链解析已取消或超时。")), false);
    }

    void MemoryWorkbenchView::leavePointerChainNavigation()
    {
        if (pointerNavigation_) return;
        cancelPointerChainResolution();
        // A pending patch must retain the chain that authorized its location.
        // Switching to another pointer requires the existing apply/discard guard.
        pointerClearAfterPending_ = hexPane_ && hexPane_->overlay().HasPendingPatches();
        if (!pointerClearAfterPending_) pointerBindings_->ClearActive();
    }

    void MemoryWorkbenchView::onPointerChainCreateRequested() { showPointerChainEditor(0); }
    void MemoryWorkbenchView::onPointerChainEditRequested(quint64 id) { if (id) showPointerChainEditor(id); }
    void MemoryWorkbenchView::onPointerChainResolveRequested(quint64 id) { resolvePointerChain(id, false); }

    void MemoryWorkbenchView::showPointerChainEditor(const std::uint64_t id)
    {
        const QPointer<MemoryWorkbenchView> self(this);
        if (!target_) return;
        const auto captured = target_->capture();
        if (!self || !target_) return;
        const auto modules = target_->pointerChainModules();
        if (!self || !target_) return;
        if (captured.session.scope != ksword::memwb::Scope::ProcessVirtual || !target_->identityAnchored()
            || captured.session.channel == ksword::memwb::Channel::Ddma || modules.empty())
        {
            if (statusBar_) statusBar_->setDiagnosticsText(
                T(QStringLiteral("请先选择已核对身份的进程目标，等待模块加载，并使用 R3、R0 或 HVM 通道。")), true);
            return;
        }
        const auto previous = id ? WorkbenchShared::Instance().AddressBook().find(id)
            : std::optional<ksword::memwb::AddressEntry>();
        if (id && (!previous || !previous->pointerChain)) return;
        auto* dialog = new QDialog(this);
        const QPointer<QDialog> safeDialog(dialog);
        dialog->setObjectName(QStringLiteral("pointer_chain_bookmark_dialog"));
        StyleSecondaryWindow(dialog);
        dialog->setWindowTitle(T(QStringLiteral("指针链书签")));
        auto* layout = new QVBoxLayout(dialog);
        StyleSecondaryContentLayout(layout);
        auto* form = new QFormLayout();
        auto* moduleCombo = new QComboBox(dialog);
        for (const auto& module : modules) moduleCombo->addItem(QString::fromUtf8(module.fullPath.c_str()));
        if (previous)
        {
            for (std::size_t i = 0; i < modules.size(); ++i)
                if (SameProgram(modules[i].fullPath, previous->pointerChain->modulePath)) moduleCombo->setCurrentIndex(static_cast<int>(i));
        }
        auto* root = new QLineEdit(previous ? QString::number(previous->rva, 16) : QStringLiteral("0"), dialog);
        root->setMaxLength(18);
        QStringList offsetValues;
        if (previous) for (const auto offset : previous->pointerChain->offsets) offsetValues << Offset(offset);
        auto* offsets = new QLineEdit(offsetValues.isEmpty() ? QStringLiteral("0") : offsetValues.join(QStringLiteral(", ")), dialog);
        offsets->setMaxLength(1024);
        auto* note = new QLineEdit(previous ? QString::fromUtf8(previous->note.c_str()) : QString(), dialog);
        note->setMaxLength(256);
        form->addRow(T(QStringLiteral("基址模块")), moduleCombo);
        form->addRow(T(QStringLiteral("根指针偏移（十六进制）")), root);
        form->addRow(T(QStringLiteral("逐级偏移（从根到目标，逗号分隔）")), offsets);
        form->addRow(T(QStringLiteral("备注")), note);
        layout->addLayout(form);
        // 既有四项共同决定链定义，保持同屏填写；长模块路径不撑宽整个窗口。
        moduleCombo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
        moduleCombo->setMinimumContentsLength(24);
        StyleSecondaryForm(form, 190);
        auto* hint = new QLabel(T(QStringLiteral("每级先读取指针，再加偏移。支持 1 至 16 级有符号十六进制偏移；仅按需解析。")), dialog);
        hint->setWordWrap(true);
        layout->addWidget(hint);
        if (const auto found = pointerTraces_.find(id); found != pointerTraces_.end())
        {
            auto* trace = new StructuredFieldView(dialog);
            trace->setDocument(found->second);
            layout->addWidget(trace);
        }
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, dialog);
        layout->addWidget(buttons);
        StyleSecondaryButtonBox(buttons);
        connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
        connect(buttons, &QDialogButtonBox::accepted, dialog,
            [self, safeDialog, captured, modules, previous, id, moduleCombo, root, offsets, note]() {
            if (!self || !safeDialog || !self->target_ || self->target_->isStale(captured.rev)) return;
            if (!self || !safeDialog) return;
            bool ok = false;
            QString rootText = root->text().trimmed();
            if (rootText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) rootText.remove(0, 2);
            const auto rva = rootText.toULongLong(&ok, 16);
            const auto index = moduleCombo->currentIndex();
            if (!ok || rootText.startsWith(QLatin1Char('-')) || rootText.startsWith(QLatin1Char('+'))
                || index < 0 || index >= static_cast<int>(modules.size()))
            {
                QMessageBox::warning(safeDialog.data(), T(QStringLiteral("指针链书签")),
                    T(QStringLiteral("根偏移越界，或逐级偏移不是 1 至 16 个有效的有符号十六进制数。")));
                return;
            }
            const auto& module = modules[static_cast<std::size_t>(index)];
            auto metadata = ksword::memwb_pointer_access::CaptureModule(captured.session, module.fullPath);
            if (!metadata.ok)
            {
                QMessageBox::warning(safeDialog.data(), T(QStringLiteral("指针链书签")), IssueText(metadata.issue));
                return;
            }
            const auto pieces = offsets->text().split(QLatin1Char(','));
            ok = !pieces.empty() && pieces.size() <= static_cast<qsizetype>(ksword::pointer_chain::MaxDepth);
            for (const auto& piece : pieces)
            {
                std::int64_t value = 0;
                if (!ksword::pointer_chain::ParseOffset(piece.toStdString(), value)) { ok = false; break; }
                metadata.definition.offsets.push_back(value);
            }
            if (!ok || rva >= metadata.definition.moduleSize
                || metadata.definition.pointerSize > metadata.definition.moduleSize - rva)
            {
                QMessageBox::warning(safeDialog.data(), T(QStringLiteral("指针链书签")),
                    T(QStringLiteral("根偏移越界，或逐级偏移不是 1 至 16 个有效的有符号十六进制数。")));
                return;
            }
            if (!self || !safeDialog || !self->target_ || self->target_->isStale(captured.rev)) return;
            if (!self || !safeDialog) return;
            const auto savedNote = note->text();
            const auto savedModuleName = module.name.empty()
                ? QFileInfo(QString::fromUtf8(module.fullPath.c_str())).fileName().toStdString() : module.name;
            auto& store = WorkbenchShared::Instance().AddressBook();
            if (previous)
            {
                const auto current = store.find(id);
                if (!current || !SameDefinition(*current, *previous)
                    || !SameProgram(current->pointerChain->processPath, metadata.definition.processPath)) return;
                if (!store.setPointerChain(id, metadata.definition, QString::fromUtf8(savedModuleName.c_str()), rva)) return;
                if (!self || !safeDialog) return;
                store.setNote(id, savedNote);
            }
            else
            {
                ksword::memwb::AddressEntry draft;
                draft.kind = ksword::memwb::EntryKind::Bookmark;
                draft.targetKey = metadata.definition.processPath;
                draft.moduleName = savedModuleName;
                draft.rva = rva;
                draft.note = savedNote.toUtf8().toStdString();
                draft.pointerChain = std::move(metadata.definition);
                if (!store.add(draft)) return;
            }
            if (self) self->cancelPointerChainResolution();
            if (safeDialog) safeDialog->accept();
        });
        dialog->resize(640, pointerTraces_.count(id) ? 500 : 300);
        dialog->exec();
        if (safeDialog) safeDialog->deleteLater();
    }

    void MemoryWorkbenchView::resolvePointerChain(const std::uint64_t id, const bool navigate, const bool disassembly)
    {
        const QPointer<MemoryWorkbenchView> self(this);
        if (!target_ || pointerResolutionBusy_) return;
        const auto entry = WorkbenchShared::Instance().AddressBook().find(id);
        if (!entry || !entry->pointerChain) return;
        if (navigate && hexPane_ && hexPane_->overlay().HasPendingPatches())
        {
            if (!target_->requestLeave(LeaveReason::PinChange) || !self) return;
        }
        if (!self || !target_) return;
        const auto captured = target_->capture();
        if (!self || !target_) return;
        auto ownedPort = WorkbenchShared::Instance().CreateIoPort();
        if (!ownedPort) return;
        const std::shared_ptr<ksword::memwb::IMemoryIoPort> port(std::move(ownedPort));
        cancelPointerChainResolution();
        const auto ticket = pointerTicket_;
        const auto cancel = std::make_shared<std::atomic<bool>>(false);
        pointerCancel_ = cancel;
        pointerResolutionBusy_ = true;
        if (statusBar_) statusBar_->setDiagnosticsText(T(QStringLiteral("正在解析指针链…")), false);
        QThreadPool::globalInstance()->start([self, entry = *entry, captured, port, ticket, cancel, navigate, disassembly]() {
            ksword::memwb_pointer_access::Resolution resolved;
            try { resolved = ksword::memwb_pointer_access::Resolve(entry, captured.session, *port, cancel); }
            catch (...) { resolved.issue = ksword::memwb_pointer_access::Issue::ReadFailed; }
            QMetaObject::invokeMethod(qApp, [self, entry, captured, resolved, ticket, navigate, disassembly]() {
                if (!self) return;
                self->pointerResolutionBusy_ = false;
                const auto current = WorkbenchShared::Instance().AddressBook().find(entry.id);
                if (ticket != self->pointerTicket_ || !self->target_ || self->target_->isStale(captured.rev)
                    || !current || !SameDefinition(entry, *current)) return;
                if (!self) return;
                const auto trace = BuildPointerTrace(resolved);
                if (self->pointerTraces_.size() >= 256) self->pointerTraces_.erase(self->pointerTraces_.begin());
                self->pointerTraces_[entry.id] = trace;
                if (self->statusBar_) self->statusBar_->setDiagnosticsDocument(trace, true);
                if (!navigate || !resolved.result.ok()) return;
                NavRequest request;
                request.scope = captured.session.scope;
                request.address = resolved.result.address;
                request.origin = NavOrigin::AddressBook;
                if (self->target_->followMode() == ksword::memwb::MemoryTargetTracker::Follow::Pinned)
                {
                    request.pid = captured.session.pid;
                    request.createTime = captured.session.processCreateTime100ns;
                }
                self->pointerNavigation_ = true;
                const auto outcome = self->openAt(request);
                if (!self) return;
                self->pointerNavigation_ = false;
                const auto latest = WorkbenchShared::Instance().AddressBook().find(entry.id);
                if (outcome != NavStatus::Ok || !latest || !SameDefinition(entry, *latest) || !self->target_) return;
                const auto currentSession = self->target_->session();
                if (!self || !ksword::memwb::SameTarget(currentSession, captured.session)) return;
                if (self->pointerBindings_->Bind({ entry, captured.session, resolved.result }))
                {
                    self->pointerClearAfterPending_ = false;
                    if (disassembly && self->subTabStack_) self->subTabStack_->setCurrentIndex(1);
                }
            }, Qt::QueuedConnection);
        });
    }

    bool MemoryWorkbenchView::validatePointerChainWrite(const ksword::memwb::MemoryTargetSession& session,
        const std::uint64_t address, const std::uint64_t length, std::string& reason)
    {
        using F = ksword::memwb::GuardResult::Failure;
        if (pointerClosing_ || !target_) { reason = "pointer-view-closed"; return false; }
        // 写前验证覆盖立即写、暂存应用与撤销；退出的独立身份不能被重用。
        if (memoryDebugMode_ && target_->livenessState() == LivenessState::Exited)
        {
            reason = T(QStringLiteral("目标进程已退出，写入已取消")).toUtf8().toStdString();
            return false;
        }
        const auto writeSession = session;
        const QPointer<MemoryWorkbenchView> self(this);
        const auto bindings = pointerBindings_;
        const auto before = target_->session();
        if (!self || !ksword::memwb::SameTarget(before, writeSession))
        { reason = T(QStringLiteral("指针链对应的进程实例或通道已改变，写入已取消。")).toUtf8().toStdString(); return false; }
        ksword::memwb_pointer_access::Resolution last;
        const auto guarded = bindings->Validate(writeSession, address, length,
            writeController_ && writeController_->isHistoryReplay(),
            [](std::uint64_t id) { return WorkbenchShared::Instance().AddressBook().find(id); },
            [&last](const auto& entry, const auto& currentSession) {
                last = {};
                auto port = WorkbenchShared::Instance().CreateIoPort();
                if (port) last = ksword::memwb_pointer_access::Resolve(entry, currentSession, *port);
                return last.result;
            });
        if (!self || !target_ || pointerClosing_) { reason = "pointer-view-closed"; return false; }
        const auto after = target_->session();
        if (!self || !ksword::memwb::SameTarget(after, writeSession))
        { reason = T(QStringLiteral("指针链对应的进程实例或通道已改变，写入已取消。")).toUtf8().toStdString(); return false; }
        if (guarded.ok) return true;
        QString text;
        switch (guarded.failure)
        {
        case F::ChangedDefinition: text = T(QStringLiteral("指针链书签已修改或删除，请重新解析后再编辑。")); break;
        case F::ChangedSession: text = T(QStringLiteral("指针链对应的进程实例或通道已改变，写入已取消。")); break;
        case F::Capacity: text = T(QStringLiteral("指针链写入历史已达到上限，请重新选择目标后继续。")); break;
        default: text = T(QStringLiteral("指针链路径或落点已改变，写入已取消。请重新解析后再编辑。")); break;
        }
        reason = (text + QStringLiteral("\n") + IssueText(last.issue)).toUtf8().toStdString();
        return false;
    }
}
