#include "../Framework.h"
#include "MemoryDebugExecutionPanel.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncUiDispatcher.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/SecondaryPageLayout.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/ResultTableHost.h"
#include "../UI/TablePresentation.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/UI_All.h"
#include <QCheckBox>
#include <QApplication>
#include <QComboBox>
#include <QDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QSignalBlocker>
#include <QThreadPool>
#include <QVBoxLayout>
#include <cstring>

namespace ks::ui
{
    namespace
    {
        QString HvmText(const char* source) { return ks::i18n::sourceText(QString::fromUtf8(source)); }
        QString HvmHex(std::uint64_t value) { return QStringLiteral("0x%1").arg(value, 0, 16).toUpper(); }
        bool ReadHex(QLineEdit* edit, std::uint64_t& value)
        {
            auto text = edit->text().trimmed();
            if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) text.remove(0, 2);
            bool ok = false;
            value = text.toULongLong(&ok, 16);
            edit->setProperty("ksword_input_invalid", !ok);
            return ok;
        }
    }

    void MemoryDebugExecutionPanel::showHvmControls()
    {
        if (hvmDialog_) { hvmDialog_->show(); hvmDialog_->raise(); return; }
        if (pid_ == 0 || busy_) return;
        auto* dialog = new QDialog(this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setObjectName(QStringLiteral("memory_debug_hvm_controls_window"));
        dialog->setWindowTitle(HvmText("无附加调试 · 断点与寄存器"));
        StyleSecondaryWindow(dialog);
        hvmDialog_ = dialog;
        hvmDialogSession_ = hvmSessionId_;
        hvmDisplayedCount_ = ~0UL;
        auto* root = new QVBoxLayout(dialog);
        root->setContentsMargins(6, 6, 6, 6);
        auto* workspace = new ParameterWorkspace(dialog, 330);
        root->addWidget(workspace);

        auto* breakpoint = new QGroupBox(HvmText("执行地址"), workspace);
        StyleParameterSection(breakpoint);
        auto* form = new QFormLayout(breakpoint);
        form->setRowWrapPolicy(QFormLayout::WrapLongRows);
        hvmAddress_ = new QLineEdit(breakpoint);
        hvmAddress_->setObjectName(QStringLiteral("noattach_breakpoint_address"));
        hvmAddress_->setPlaceholderText(HvmText("十六进制用户地址"));
        if (stopped_) hvmAddress_->setText(HvmHex(hvmResponse_.rip));
        form->addRow(HvmText("地址"), hvmAddress_);
        auto* once = new QCheckBox(HvmText("命中一次后停用"), breakpoint);
        form->addRow(once);
        auto* scope = new QLabel(HvmText("只作用于当前选定线程。最多 8 个执行地址；页面映射变化后须删除并重新安装。"), breakpoint);
        scope->setWordWrap(true);
        scope->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        form->addRow(scope);
        workspace->parameters()->addWidget(breakpoint);

        auto* registers = new QGroupBox(HvmText("整数寄存器编辑"), workspace);
        StyleParameterSection(registers);
        auto* registerForm = new QFormLayout(registers);
        registerForm->setRowWrapPolicy(QFormLayout::WrapLongRows);
        hvmRegister_ = new QComboBox(registers);
        hvmRegister_->addItems({QStringLiteral("RAX"), QStringLiteral("RCX"), QStringLiteral("RDX"), QStringLiteral("RBX"),
            QStringLiteral("RBP"), QStringLiteral("RSI"), QStringLiteral("RDI"), QStringLiteral("R8"), QStringLiteral("R9"),
            QStringLiteral("R10"), QStringLiteral("R11"), QStringLiteral("R12"), QStringLiteral("R13"), QStringLiteral("R14"),
            QStringLiteral("R15"), QStringLiteral("RIP"), QStringLiteral("RSP")});
        hvmValue_ = new QLineEdit(registers);
        hvmValue_->setObjectName(QStringLiteral("noattach_register_value"));
        hvmValue_->setPlaceholderText(HvmText("十六进制新值"));
        registerForm->addRow(HvmText("寄存器"), hvmRegister_);
        registerForm->addRow(HvmText("新值"), hvmValue_);
        hvmWrite_ = new QPushButton(HvmText("提交寄存器"), registers);
        registerForm->addRow(hvmWrite_);
        auto* contextNote = new QLabel(HvmText("提交只接受当前停点。新现场出现前显示为等待；不编辑 RFLAGS、DR 或 SIMD/XSTATE。"), registers);
        contextNote->setWordWrap(true);
        contextNote->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        registerForm->addRow(contextNote);
        workspace->parameters()->addWidget(registers);

        hvmAdd_ = new QPushButton(HvmText("添加断点"), dialog);
        hvmRunTo_ = new QPushButton(HvmText("运行到地址"), dialog);
        ApplyFlatButtonTheme(hvmRunTo_, FlatButtonTone::Accent);
        workspace->actions()->addWidget(hvmAdd_);
        workspace->actions()->addWidget(hvmRunTo_);
        NormalizeToolbarRow(workspace->actions());

        hvmDetailStatus_ = new QLabel(dialog);
        hvmDetailStatus_->setObjectName(QStringLiteral("noattach_stop_identity"));
        hvmDetailStatus_->setWordWrap(true);
        hvmDetailStatus_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        workspace->results()->addWidget(hvmDetailStatus_);
        auto* resultActions = new QHBoxLayout();
        auto* title = new QLabel(HvmText("本会话断点"), dialog);
        resultActions->addWidget(title);
        resultActions->addStretch();
        hvmRemove_ = new QPushButton(HvmText("删除所选断点"), dialog);
        resultActions->addWidget(hvmRemove_);
        NormalizeToolbarRow(resultActions);
        workspace->results()->addLayout(resultActions);
        hvmBreakpoints_ = new QTableWidget(0, 4, dialog);
        hvmBreakpoints_->setObjectName(QStringLiteral("noattach_breakpoints"));
        hvmBreakpoints_->setHorizontalHeaderLabels({HvmText("断点 ID"), HvmText("地址"), HvmText("类型"), HvmText("状态")});
        hvmBreakpoints_->setSelectionBehavior(QAbstractItemView::SelectRows);
        hvmBreakpoints_->setSelectionMode(QAbstractItemView::SingleSelection);
        hvmBreakpoints_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        hvmBreakpoints_->horizontalHeader()->setStretchLastSection(true);
        ApplyTablePresentation(hvmBreakpoints_);
        SetTablePresentationDensity(hvmBreakpoints_, TablePresentationDensity::Compact);
        ResultTableCapabilities capabilities;
        capabilities.actionBar = TableActionBarMode::Compact;
        (void)ResultTableHost::ensure(hvmBreakpoints_)->bindModel(hvmBreakpoints_->model(),
            {{0, QStringLiteral("id")}, {1, QStringLiteral("address")}, {2, QStringLiteral("kind")}, {3, QStringLiteral("state")}}, capabilities);
        workspace->results()->addWidget(hvmBreakpoints_, 1);
        workspace->finish();

        const auto add = [this, once](bool runTo)
        {
            std::uint64_t address = 0;
            if (!ReadHex(hvmAddress_, address) || address == 0)
            { hvmDetailStatus_->setText(HvmText("请输入有效的十六进制用户地址。")); return; }
            KSWORD_ARK_HVM_NOATTACH_REQUEST request{};
            request.operation = runTo ? KSWORD_ARK_HVM_NOATTACH_RUN_TO : KSWORD_ARK_HVM_NOATTACH_ADD_BREAKPOINT;
            request.address = address;
            request.breakpointFlags = once->isChecked() ? KSWORD_ARK_HVM_NOATTACH_BP_ONESHOT : 0;
            submitHvm(request);
        };
        connect(hvmAdd_, &QPushButton::clicked, dialog, [add]() { add(false); });
        connect(hvmRunTo_, &QPushButton::clicked, dialog, [add]() { add(true); });
        connect(hvmRemove_, &QPushButton::clicked, dialog, [this]()
        {
            const int row = hvmBreakpoints_->currentRow();
            if (row < 0 || hvmBreakpoints_->item(row, 0) == nullptr) return;
            KSWORD_ARK_HVM_NOATTACH_REQUEST request{};
            request.operation = KSWORD_ARK_HVM_NOATTACH_REMOVE_BREAKPOINT;
            request.breakpointId = hvmBreakpoints_->item(row, 0)->data(Qt::UserRole).toUInt();
            submitHvm(request);
        });
        connect(hvmWrite_, &QPushButton::clicked, dialog, [this]()
        {
            std::uint64_t value = 0;
            if (!ReadHex(hvmValue_, value))
            { hvmDetailStatus_->setText(HvmText("请输入有效的十六进制寄存器值。")); return; }
            const auto index = static_cast<unsigned int>(hvmRegister_->currentIndex());
            if (index >= 17) return;
            KSWORD_ARK_HVM_NOATTACH_REQUEST request{};
            request.operation = KSWORD_ARK_HVM_NOATTACH_SET_GPR;
            request.registerMask = 1ULL << index;
            // memcpy 避免跨结构成员做 C++ 数组指针运算。
            std::memcpy(reinterpret_cast<unsigned char*>(&request.registers) + index * sizeof(value), &value, sizeof(value));
            submitHvm(request);
        });
        connect(hvmBreakpoints_, &QTableWidget::itemSelectionChanged, dialog, [this]() { updateHvmControls(); });
        applyResponsiveWindowGeometry(dialog, this, QSize(1000, 660), QSize(640, 440));
        updateHvmControls();
        dialog->show();
    }

    void MemoryDebugExecutionPanel::submitHvm(KSWORD_ARK_HVM_NOATTACH_REQUEST request)
    {
        if ((qApp && qApp->property("ksword_memory_quit_guard_active").toBool()) || busy_ || !stopped_ ||
            hvmSessionId_ == 0 || !hvmDialog_ || hvmDialogSession_ != hvmSessionId_) return;
        request.sessionId = hvmSessionId_;
        request.stopId = stopId_;
        request.ownerCreationTime = ownerCreation_;
        request.processId = hvmResponse_.processId;
        request.threadId = hvmResponse_.threadId;
        request.processCreationTime = hvmResponse_.processCreationTime;
        request.threadCreationTime = hvmResponse_.threadCreationTime;
        busy_ = true;
        fastPollBudget_ = 20;
        updateActions();
        const auto epoch = epoch_;
        const auto handle = hvmHandle_;
        const auto dispatcher = dispatcher_;
        QThreadPool::globalInstance()->start([this, epoch, handle, dispatcher, request]()
        {
            const auto result = ksword::ark::controlHvmNoAttach(request, handle.get());
            dispatcher->post([this, epoch, result]()
            {
                busy_ = false;
                if (epoch == epoch_) applyHvm(result);
                updateActions();
            });
        });
    }

    void MemoryDebugExecutionPanel::updateHvmControls()
    {
        if (!hvmDialog_) return;
        const bool same = hvmSessionId_ != 0 && hvmDialogSession_ == hvmSessionId_;
        const bool canEdit = same && !busy_ && stopped_ && hvmState_ == KSWORD_ARK_HVM_NOATTACH_STOPPED;
        const bool breakpoints = canEdit && (hvmResponse_.capabilities & KSWORD_ARK_HVM_NOATTACH_CAP_BREAKPOINT) != 0;
        hvmAdd_->setEnabled(breakpoints);
        hvmRunTo_->setEnabled(breakpoints);
        hvmRemove_->setEnabled(breakpoints && hvmBreakpoints_->currentRow() >= 0);
        hvmWrite_->setEnabled(canEdit && (hvmResponse_.capabilities & KSWORD_ARK_HVM_NOATTACH_CAP_SET_GPR) != 0);
        hvmDetailStatus_->setText(HvmText("PID %1 · TID %2 · 会话 %3 · 停点 %4\n%5")
            .arg(hvmResponse_.processId ? hvmResponse_.processId : pid_).arg(hvmResponse_.threadId).arg(hvmDialogSession_)
            .arg(stopped_ ? stopId_ : 0).arg(same ? status_->text() : hvmDialogSession_ == 0
                ? HvmText("尚未打开执行会话；参数草稿仅在本窗口保留。启动后重新打开本工具页。")
                : HvmText("原调试会话已关闭；重新打开工具页后才能操作新会话。")));
        const auto count = hvmResponse_.breakpointCount;
        if (count == hvmDisplayedCount_ && std::memcmp(hvmDisplayedRows_.data(), hvmResponse_.breakpoints,
                                                    sizeof(hvmResponse_.breakpoints)) == 0) return;
        unsigned int selectedId = 0;
        const auto row = hvmBreakpoints_->currentRow();
        if (row >= 0 && hvmBreakpoints_->item(row, 0)) selectedId = hvmBreakpoints_->item(row, 0)->data(Qt::UserRole).toUInt();
        const QSignalBlocker blocker(hvmBreakpoints_);
        hvmBreakpoints_->setRowCount(static_cast<int>(count));
        for (unsigned long i = 0; i < count; ++i)
        {
            const auto& bp = hvmResponse_.breakpoints[i];
            const QString values[]{QString::number(bp.id), HvmHex(bp.address),
                (bp.flags & KSWORD_ARK_HVM_NOATTACH_BP_ONESHOT) ? HvmText("一次性") : HvmText("持续"),
                (bp.flags & KSWORD_ARK_HVM_NOATTACH_BP_STALE) ? HvmText("映射已变化，需重装") :
                (bp.flags & KSWORD_ARK_HVM_NOATTACH_BP_CONSUMED) ? HvmText("已消费") : HvmText("已安装")};
            for (int column = 0; column < 4; ++column)
            {
                auto* item = new QTableWidgetItem(values[column]);
                item->setData(Qt::UserRole, static_cast<unsigned int>(bp.id));
                hvmBreakpoints_->setItem(static_cast<int>(i), column, item);
            }
            if (bp.id == selectedId) hvmBreakpoints_->selectRow(static_cast<int>(i));
        }
        std::memcpy(hvmDisplayedRows_.data(), hvmResponse_.breakpoints, sizeof(hvmResponse_.breakpoints));
        hvmDisplayedCount_ = count;
        hvmRemove_->setEnabled(breakpoints && hvmBreakpoints_->currentRow() >= 0);
    }
}
