#include "KernelDumpStackWindow.h"
#include "KernelDumpStackClient.h"
#include "ThreadStackWindow.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncOperation.h"
#include "../UI/DetailDialogChrome.h"
#include "../UI/DetailPresentation.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/TablePresentation.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/UI_All.h"
#include "../UI/VisibleTableWidget.h"

#include <QDateTime>
#include <QDialog>
#include <QFileDialog>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QGroupBox>
#include <QHeaderView>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

namespace
{
    using namespace ks::kernel_dump;

    // 只格式化 DbgEng 返回的地址与帧信息，不合成缺失的调用帧。
    QString Hex(std::uint64_t value)
    {
        return QStringLiteral("0x%1").arg(static_cast<qulonglong>(value), 0, 16);
    }

    // 将同一次展开的快照来源、目标、状态和帧一起提交到结果视口。
    void Publish(QTableWidget& table, QLabel& state, const ThreadStackResult& result)
    {
        const auto reason = result.status == ThreadStackStatus::Ok ? QStringLiteral("转储栈展开完成") :
            result.status == ThreadStackStatus::Partial ? QStringLiteral("转储栈仅部分展开") : QStringLiteral("转储栈不可用");
        const auto when = result.dumpTimeUnixSeconds ?
            QDateTime::fromSecsSinceEpoch(result.dumpTimeUnixSeconds).toString(Qt::ISODate) : QStringLiteral("—");
        state.setText(QStringLiteral("%1 · PID %2 · TID %3 · %4\n%5\n%6")
            .arg(ks::i18n::displayText(reason)).arg(result.processId).arg(result.threadId)
            .arg(when, QString::fromStdWString(result.dumpPath), ks::i18n::displayText(QString::fromStdWString(result.diagnostic))));
        ks::ui::ApplyStatusRole(&state, result.frames.empty() ? ks::ui::StatusRole::Warning : ks::ui::StatusRole::Info);
        table.setRowCount(static_cast<int>(result.frames.size()));
        for (const auto& frame : result.frames)
        {
            const auto row = static_cast<int>(frame.index); // 使用与 CLI 一致的零基连续帧号。
            auto name = QString::fromStdWString(frame.symbol.empty() ? frame.module : frame.symbol);
            if (!frame.symbol.empty() && frame.displacement)
            {
                name += QLatin1Char('+') + Hex(frame.displacement);
            }
            const QStringList cells{QString::number(row), Hex(frame.instruction), Hex(frame.stack),
                frame.returnAddress ? Hex(frame.returnAddress) : QStringLiteral("—"), name};
            for (int column = 0; column < cells.size(); ++column)
            {
                auto* item = new QTableWidgetItem(cells[column]); // 结果项归表格所有。
                item->setToolTip(cells[column]);
                table.setItem(row, column, item);
            }
        }
    }
}

void ShowKernelDumpStackWindow(QWidget* parent, const ThreadStackTarget& target)
{
    auto* dialog = new QDialog(parent); // 独立参数与结果工具窗，与现场刷新隔离。
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setProperty("ksword_detail_keep_layout", true);
    dialog->setWindowTitle(QStringLiteral("内核转储调用栈"));
    ks::ui::applyResponsiveWindowGeometry(dialog, parent, QSize(1040, 650), QSize(640, 430));
    auto* outer = new QVBoxLayout(dialog); // 根布局由详情外壳负责。
    auto* workspace = new ks::ui::ParameterWorkspace(dialog, 340); // 窄窗仍由框架切换排列。
    outer->addWidget(workspace);
    auto* group = new QGroupBox(QStringLiteral("转储目标"), workspace);
    auto* form = new QFormLayout(group); // 输入留在参数区，结果和动作独立。
    form->setRowWrapPolicy(QFormLayout::WrapLongRows);
    auto* dump = new QLineEdit(group);
    dump->setReadOnly(true);
    auto* browse = new QPushButton(QStringLiteral("选择转储…"), group);
    browse->setToolTip(QStringLiteral("选择本地 Windows 内核转储"));
    auto* pid = new QLineEdit(QString::number(target.processId), group); // 可指定旧转储中的其他进程。
    auto* tid = new QLineEdit(QString::number(target.threadId), group); // 使用转储内的 Windows TID。
    auto* symbols = new QLineEdit(group); // 不填时不自动访问网络。
    auto* info = new QLabel(QStringLiteral("只分析转储时刻的线程。使用当前行的 PID 和 TID 时核验创建时间；更换编号后仅核验转储内的 PID 和 TID。"), group);
    info->setWordWrap(true);
    form->addRow(QStringLiteral("转储文件"), dump);
    form->addRow(QString(), browse);
    form->addRow(QStringLiteral("PID"), pid);
    form->addRow(QStringLiteral("TID"), tid);
    form->addRow(QStringLiteral("符号路径（可选）"), symbols);
    form->addRow(info);
    ks::ui::StyleParameterSection(group);
    workspace->parameters()->addWidget(group);
    workspace->parameters()->addStretch();
    auto* run = new QPushButton(QStringLiteral("展开转储栈"), workspace);
    run->setToolTip(QStringLiteral("从转储恢复并验证目标线程的内核帧"));
    ks::ui::ApplyFlatButtonTheme(run, ks::ui::FlatButtonTone::Accent, ks::ui::FlatButtonAppearance::Solid);
    workspace->actions()->addWidget(run);
    ks::ui::NormalizeToolbarRow(workspace->actions());

    auto* state = new QLabel(QStringLiteral("选择转储后运行；不读取实时内核。"), workspace);
    state->setWordWrap(true);
    state->setTextFormat(Qt::PlainText);
    state->setTextInteractionFlags(Qt::TextSelectableByMouse);
    workspace->results()->addWidget(state);
    auto* table = new QTableWidget(0, 5, workspace); // 调试帧表保留横向滚动。
    table->setHorizontalHeaderLabels({QStringLiteral("#"), ks::i18n::displayText(QStringLiteral("地址")),
        ks::i18n::displayText(QStringLiteral("栈指针")), ks::i18n::displayText(QStringLiteral("返回地址")),
        ks::i18n::displayText(QStringLiteral("符号"))});
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->horizontalHeader()->setStretchLastSection(true);
    ks::ui::SetTableActionBarMode(table, ks::ui::TableActionBarMode::Compact);
    ks::ui::ApplyTablePresentation(table);
    workspace->results()->addWidget(table, 1);
    workspace->finish();
    ks::ui::ApplyDetailDialogChrome(dialog);

    // 原生文件选择器仅更新草稿，点击执行才打开转储。
    QObject::connect(browse, &QPushButton::clicked, dialog, [dialog, dump]()
    {
        const auto path = QFileDialog::getOpenFileName(dialog, QStringLiteral("选择转储…"), {}, QStringLiteral("*.dmp"));
        if (!path.isEmpty())
        {
            dump->setText(path);
        }
    });
    auto* operation = new ks::ui::AsyncOperation(dialog); // 共享异步生命周期；关窗不会发布旧回执。
    QObject::connect(run, &QPushButton::clicked, dialog, [operation, run, dump, pid, tid, symbols, state, table, target]()
    {
        ThreadStackRequest request; // 在执行时冻结全部输入和目标身份。
        request.dumpPath = dump->text().toStdWString();
        request.processId = pid->text().toUInt();
        request.threadId = tid->text().toUInt();
        if (request.dumpPath.empty() || !request.processId || !request.threadId)
        {
            state->setText(QStringLiteral("请填写转储路径、PID 和 TID。"));
            ks::ui::ApplyStatusRole(state, ks::ui::StatusRole::Warning);
            return;
        }
        if (request.processId == target.processId && request.threadId == target.threadId)
        {
            request.processCreationTime100ns = target.processCreationTime100ns;
            request.threadCreationTime100ns = target.threadCreationTime100ns;
        }
        request.symbolPath = symbols->text().trimmed().toStdWString();
        run->setEnabled(false);
        table->setRowCount(0); // 加载期间不把上一次帧显示在新标签下。
        state->setText(QStringLiteral("正在展开转储栈…"));
        ks::ui::ApplyStatusRole(state, ks::ui::StatusRole::Info);
        operation->submit<ThreadStackRequest, ThreadStackResult>(request,
            [](const ThreadStackRequest& frozen, const ks::ui::AsyncOperationToken& token)
            {
                return token.isCanceled() ? ThreadStackResult{} : RunKernelDumpStackCli(frozen);
            }, [run, table, state](const ThreadStackResult& result, std::uint64_t)
            {
                Publish(*table, *state, result);
                run->setEnabled(true);
                return true;
            }, [run, state](std::exception_ptr)
            {
                state->setText(QStringLiteral("转储栈不可用"));
                ks::ui::ApplyStatusRole(state, ks::ui::StatusRole::Error);
                run->setEnabled(true);
            });
    });
    dialog->show();
}
