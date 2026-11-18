#include "ProcessDetectionSelector.h"
#include "ProcessResearchCatalog.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/SecondaryPageLayout.h"
#include "../UI/UI_All.h"
#include "../UI/TablePresentation.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/VisibleTableWidget.h"
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QTabWidget>
#include <QHeaderView>
#include <QVBoxLayout>
#include <bit>

namespace ksword::detection
{
    using ks::i18n::sourceText;

    ProcessDetectionSelector::ProcessDetectionSelector(bool deep, QWidget* parent)
        : QPushButton(parent), m_deep(deep), m_selected(DetectionDefaults(deep))
    {
        setObjectName(QStringLiteral("process_detection_selector"));
        connect(this, &QPushButton::clicked, this, &ProcessDetectionSelector::edit);
        updateCaption();
    }

    void ProcessDetectionSelector::updateCaption()
    {
        setText(sourceText(QStringLiteral("检测方法（%1）…")).arg(m_selected.research.count() + std::popcount(m_selected.sources)));
    }

    void ProcessDetectionSelector::edit()
    {
        auto* dialog = new QDialog(window());
        dialog->setWindowModality(Qt::WindowModal);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setWindowTitle(sourceText(QStringLiteral("选择检测方法")));
        ks::ui::StyleSecondaryManagerWindow(dialog);
        ks::ui::applyResponsiveWindowGeometry(dialog, this, {830, 660}, {360, 320});
        auto* outer = new QVBoxLayout(dialog);
        auto* tabs = new QTabWidget(dialog);
        ks::ui::StyleSecondaryTabs(tabs);
        outer->addWidget(tabs, 1);
        auto makeList = [&](const QString& title, bool showSource) {
            auto* page = new QWidget(tabs);
            auto* column = new QVBoxLayout(page);
            auto* filterRow = new QHBoxLayout;
            auto* filter = new QLineEdit(page);
            filter->setPlaceholderText(sourceText(QStringLiteral("搜索编号、检测方法或耗时")));
            filter->setClearButtonEnabled(true);
            ks::ui::StyleSearchField(filter);
            auto* all = new QPushButton(sourceText(QStringLiteral("选中可见项")), page);
            auto* none = new QPushButton(sourceText(QStringLiteral("清除可见项")), page);
            filterRow->addWidget(filter, 1);
            filterRow->addWidget(all);
            filterRow->addWidget(none);
            ks::ui::NormalizeToolbarRow(filterRow);
            column->addLayout(filterRow);
            auto* table = new ks::ui::VisibleTableWidget(page);
            QStringList headers{sourceText(QStringLiteral("检测方法")), sourceText(QStringLiteral("预计耗时"))};
            if (showSource) headers.append(sourceText(QStringLiteral("数据来源")));
            table->setColumnCount(headers.size());
            table->setHorizontalHeaderLabels(headers);
            table->verticalHeader()->hide();
            table->setWordWrap(true);
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
            table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
            if (showSource) table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
            ks::ui::SetTableActionBarMode(table, ks::ui::TableActionBarMode::None);
            ks::ui::ApplyTablePresentation(table);
            column->addWidget(table, 1);
            connect(filter, &QLineEdit::textChanged, table, [table](const QString& text) {
                for (int r = 0; r < table->rowCount(); ++r)
                {
                    bool matched = false;
                    for (int col = 0; col < table->columnCount(); ++col)
                        matched |= table->item(r,col)->text().contains(text.trimmed(), Qt::CaseInsensitive);
                    table->setRowHidden(r, !matched);
                }
            });
            const auto checkVisible = [table](Qt::CheckState state) {
                for (int r = 0; r < table->rowCount(); ++r)
                    if (!table->isRowHidden(r)) table->item(r,0)->setCheckState(state);
            };
            connect(all, &QPushButton::clicked, table, [checkVisible] { checkVisible(Qt::Checked); });
            connect(none, &QPushButton::clicked, table, [checkVisible] { checkVisible(Qt::Unchecked); });
            tabs->addTab(page, title);
            return table;
        };
        auto addMethod = [](QTableWidget* table, const QString& title, Cost cost, bool checked, const QString& origin = {}) {
            const int row = table->rowCount();
            table->insertRow(row);
            auto* item = new QTableWidgetItem(title);
            item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsUserCheckable);
            item->setToolTip(title);
            item->setCheckState(checked ? Qt::Checked : Qt::Unchecked);
            table->setItem(row, 0, item);
            const auto duration = cost == Cost::Fast ? QStringLiteral("预计较快") :
                cost == Cost::Moderate ? QStringLiteral("预计中等耗时") : QStringLiteral("预计较慢");
            table->setItem(row, 1, new QTableWidgetItem(sourceText(duration)));
            if (table->columnCount() == 3) table->setItem(row, 2, new QTableWidgetItem(sourceText(origin)));
        };
        auto* research = makeList(sourceText(QStringLiteral("研究点（1–66）")), true);
        for (const auto& point : ResearchCatalog())
            addMethod(research, QStringLiteral("%1. %2").arg(point.id).arg(sourceText(point.name)), point.cost,
                m_selected.research.test(point.id-1), ResearchSource(point));
        auto* sourcesTable = makeList(sourceText(QStringLiteral("按采集来源选择")), false);
        const auto methods = Methods();
        for (const auto& method : methods)
            addMethod(sourcesTable, sourceText(method.name), method.cost, (m_selected.sources & method.bit) != 0);

        auto* sources = new QGroupBox(sourceText(QStringLiteral("采集输入")), tabs);
        ks::ui::StyleSecondarySection(sources);
        auto* paths = new QFormLayout(sources);
        ks::ui::StyleSecondaryForm(paths);
        auto addPath = [&](const QString& label, const QString& current, bool directory, const QString& filter) {
            auto* row = new QWidget(sources);
            auto* layout = new QHBoxLayout(row);
            layout->setContentsMargins(0, 0, 0, 0);
            auto* edit = new QLineEdit(current, row);
            edit->setClearButtonEnabled(true);
            auto* browse = new QPushButton(sourceText(QStringLiteral("浏览…")), row);
            layout->addWidget(edit, 1);
            layout->addWidget(browse);
            connect(browse, &QPushButton::clicked, dialog, [=]() {
                const auto path = directory ? QFileDialog::getExistingDirectory(dialog, label, edit->text())
                    : QFileDialog::getOpenFileName(dialog, label, edit->text(), filter);
                if (!path.isEmpty()) edit->setText(path);
            });
            paths->addRow(label, row);
            return edit;
        };
        auto* mount = addPath(sourceText(QStringLiteral("MemProcFS 挂载目录")), m_inputs.memProcFsRoot, true, {});
        auto* vol = addPath(sourceText(QStringLiteral("Volatility 3 可执行文件")), m_inputs.volatilityProgram, false, QStringLiteral("*.exe"));
        auto* dump = addPath(sourceText(QStringLiteral("内存镜像")), m_inputs.memoryImage, false, {});
        auto* etl = addPath(sourceText(QStringLiteral("ETW 跟踪文件")), m_inputs.eventTraceFile, false, QStringLiteral("*.etl"));
        auto* flat = addPath(sourceText(QStringLiteral("平坦物理镜像（偏移即物理地址）")), m_inputs.flatPhysicalImage, false, {});
        auto* guest = addPath(sourceText(QStringLiteral("来宾 WMI 进程 CSV")), m_inputs.guestProcessFile, false, QStringLiteral("*.csv"));
        auto* pt = addPath(sourceText(QStringLiteral("Intel PT 原始跟踪")), m_inputs.processorTraceFile, false, {});
        auto* xen = addPath(sourceText(QStringLiteral("Xen HVM 原始跟踪")), m_inputs.xenTraceFile, false, {});
        auto* ptTool = addPath(sourceText(QStringLiteral("Intel PT 解码器 ptdump.exe")), m_inputs.processorTraceTool, false, QStringLiteral("*.exe"));
        auto* debugger = addPath(sourceText(QStringLiteral("Windows 内核调试工具")), m_inputs.debuggerProgram, false, QStringLiteral("*.exe"));
        auto* server = new QLineEdit(m_inputs.debuggerTarget, sources);
        paths->addRow(sourceText(QStringLiteral("本机 DbgEng 服务管道名")), server);
        auto* vmm = addPath(sourceText(QStringLiteral("MemProcFS 的 vmm.dll")), m_inputs.memProcFsLibrary, false, QStringLiteral("*.dll"));
        auto* vmiMount = addPath(sourceText(QStringLiteral("VMI 挂载目录")), m_inputs.vmiMountRoot, true, {});
        auto* dmaMount = addPath(sourceText(QStringLiteral("只读 DMA 挂载目录")), m_inputs.dmaMountRoot, true, {});
        auto* savedState = addPath(sourceText(QStringLiteral("Hyper-V 已保存状态（.vmrs）")), m_inputs.hypervSavedState, false, QStringLiteral("*.vmrs"));
        auto* vmx = new QLineEdit(m_inputs.vmwareProcessId, sources);
        paths->addRow(sourceText(QStringLiteral("VMI 目标（VMware PID / Hyper-V 名称或 GUID）")), vmx);
        tabs->addTab(ks::ui::CreateSecondaryFormScroll(sources, tabs), sourceText(QStringLiteral("采集输入")));
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel | QDialogButtonBox::RestoreDefaults, dialog);
        ks::ui::StyleSecondaryButtonBox(buttons);
        outer->addWidget(buttons);
        connect(buttons->button(QDialogButtonBox::RestoreDefaults), &QPushButton::clicked, this, [this, research, sourcesTable, methods]() {
            const auto defaults = DetectionDefaults(m_deep);
            for (const auto& p : ResearchCatalog())
                research->item(p.id-1,0)->setCheckState(defaults.research.test(p.id-1) ? Qt::Checked : Qt::Unchecked);
            for (int i=0; i<methods.size(); ++i)
                sourcesTable->item(i,0)->setCheckState((defaults.sources & methods[i].bit) ? Qt::Checked : Qt::Unchecked);
        });
        connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
        connect(buttons, &QDialogButtonBox::accepted, dialog, &QDialog::accept);
        connect(dialog, &QDialog::accepted, this, [=, this]() {
            m_selected = {};
            for (const auto& p : ResearchCatalog())
                m_selected.research.set(p.id-1, research->item(p.id-1,0)->checkState() == Qt::Checked);
            for (int i=0; i<methods.size(); ++i)
                if (sourcesTable->item(i,0)->checkState() == Qt::Checked) m_selected.sources |= methods[i].bit;
            m_inputs.memProcFsRoot = mount->text().trimmed();
            m_inputs.volatilityProgram = vol->text().trimmed();
            m_inputs.memoryImage = dump->text().trimmed();
            m_inputs.eventTraceFile = etl->text().trimmed();
            m_inputs.flatPhysicalImage = flat->text().trimmed();
            m_inputs.guestProcessFile = guest->text().trimmed();
            m_inputs.processorTraceFile = pt->text().trimmed();
            m_inputs.xenTraceFile = xen->text().trimmed();
            m_inputs.processorTraceTool = ptTool->text().trimmed();
            m_inputs.debuggerProgram = debugger->text().trimmed();
            m_inputs.debuggerTarget = server->text().trimmed();
            m_inputs.memProcFsLibrary = vmm->text().trimmed();
            m_inputs.vmiMountRoot = vmiMount->text().trimmed();
            m_inputs.dmaMountRoot = dmaMount->text().trimmed();
            m_inputs.hypervSavedState = savedState->text().trimmed();
            m_inputs.vmwareProcessId = vmx->text().trimmed();
            updateCaption();
        });
        dialog->open();
    }
}
