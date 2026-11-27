#include "../Framework.h"
#include "NetworkTrafficPane.h"
#include "NetworkTrafficWorker.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectStorage.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncOperation.h"
#include "../UI/CodeEditorWidget.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/ThemeAccentIcon.h"

#include <QComboBox>
#include <QEvent>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QTabWidget>
#include <QVBoxLayout>
#include <limits>

namespace ks::action_analyze {
namespace project = Ksword::ActionAnalyze;
using ks::i18n::sourceText;

// 参数/执行页复用ParameterWorkspace，结果字段与原字节各自保留完整文档工具。
NetworkTrafficPane::NetworkTrafficPane(QWidget* parent) : QWidget(parent)
{
    auto* root = new QVBoxLayout(this); // 外围只有一层6px等边留白。
    root->setContentsMargins(6, 6, 6, 6);
    auto* workspace = new ks::ui::ParameterWorkspace(this, 420); // 参数独立滚动，动作固定。
    root->addWidget(workspace);
    auto* section = new QGroupBox(sourceText(QStringLiteral("网络流量采集参数")), workspace); // 标题保留原控件。
    m_section = section;
    auto* form = new QFormLayout(section); // 自然高度表单，窄窗允许标签换行。
    m_form = form;
    form->setRowWrapPolicy(QFormLayout::WrapLongRows);
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    form->setSpacing(8);

    auto* hint = new QLabel(section); // 操作步骤与真实归属限制分别由本说明和结果回执承担。
    m_hint = hint;
    hint->setWordWrap(true);
    form->addRow(hint);
    m_project = new QLineEdit(section);
    auto* browse = new QPushButton(section); // 选择器只修改下一次执行草稿。
    m_browse = browse;
    form->addRow(QStringLiteral("项目路径"), m_project);
    form->addRow(browse);
    m_sample = new QLineEdit(section);
    form->addRow(QStringLiteral("已有采样 UUID"), m_sample);
    m_pid = new QLineEdit(section);
    form->addRow(QStringLiteral("目标 PID"), m_pid);
    m_creation = new QLineEdit(section);
    form->addRow(QStringLiteral("创建 FILETIME"), m_creation);

    // 来源显式冻结，既有WFP模式只读全局ring，不接管其启停开关。
    m_source = new QComboBox(section);
    m_source->addItem(QStringLiteral("raw-socket"));
    m_source->addItem(QStringLiteral("existing-wfp"));
    form->addRow(QStringLiteral("采集来源"), m_source);
    m_duration = new QSpinBox(section);
    m_duration->setRange(100, 60000);
    m_duration->setValue(5000);
    m_duration->setSuffix(QStringLiteral(" ms"));
    form->addRow(QStringLiteral("采集时长"), m_duration);
    m_ordinal = new QLineEdit(QStringLiteral("0"), section);
    form->addRow(QStringLiteral("网络段号（0 为最新）"), m_ordinal);
    m_sequence = new QLineEdit(section);
    form->addRow(QStringLiteral("记录序号（可选）"), m_sequence);
    ks::ui::StyleParameterSection(section);
    workspace->parameters()->addWidget(section);
    workspace->parameters()->addStretch();

    // 三个动作紧凑固定；复杂的采集/回读保留文字以说明真实作用范围。
    m_capture = new QPushButton(workspace);
    ks::ui::ApplyFlatButtonTheme(m_capture, ks::ui::FlatButtonTone::Accent);
    m_read = new QPushButton(workspace);
    m_cancel = new QPushButton(workspace); // 停止继续使用共享图标尺寸，仅辅助名称参与翻译。
    KswordTheme::ApplyStandardIconButtonMetrics(m_cancel);
    ks::ui::SetThemeButtonIcon(m_cancel, QIcon(QStringLiteral(":/Icon/process_stop.svg")));
    workspace->actions()->addWidget(m_capture);
    workspace->actions()->addWidget(m_read);
    workspace->actions()->addWidget(m_cancel);

    m_status = new QLabel(workspace);
    m_status->setWordWrap(true);
    workspace->results()->addWidget(m_status);
    auto* tabs = new QTabWidget(workspace); // 回执与字节同属一个结果身份。
    m_tabs = tabs;
    m_fields = new ks::ui::StructuredFieldView(tabs);
    m_fields->setValueModelProjection();
    m_bytes = new CodeEditorWidget(tabs);
    m_bytes->setReadOnly(true);
    m_bytes->setReadOnlyExportEnabled(true);
    tabs->addTab(m_fields, QString());
    tabs->addTab(m_bytes, QString());
    ks::ui::StylePageTabs(tabs);
    workspace->results()->addWidget(tabs, 1);
    // 共享首次布局前准备当前语言文字，按钮度量按真实标题计算。
    setStatus(QStringLiteral("尚未执行；请选择已有项目并填写采样 UUID。"));
    retranslate();
    ks::ui::NormalizeToolbarRow(workspace->actions());
    workspace->finish();

    // 接受事务不合并，关闭只撤回UI回投；取消位由worker持有直到来源清退完成。
    m_worker = new ks::ui::AsyncOperation(this);
    m_worker->setStateChangedCallback([this]()
    {
        updateActions();
    });
    connect(browse, &QPushButton::clicked, this, [this]()
    {
        chooseProject();
    });
    connect(m_capture, &QPushButton::clicked, this, [this]()
    {
        execute(true);
    });
    connect(m_read, &QPushButton::clicked, this, [this]()
    {
        execute(false);
    });
    connect(m_cancel, &QPushButton::clicked, this, [this]()
    {
        if (m_cancelled)
        {
            m_cancelled->store(true);
            setStatus(QStringLiteral("正在停止采集并保存剩余数据…"));
            updateActions();
        }
    });
    updateActions();
}

// 更新当前语言的原控件；字段文档由StructuredFieldView自行处理语言事件。
void NetworkTrafficPane::retranslate()
{
    m_section->setTitle(sourceText(QStringLiteral("网络流量采集参数")));
    m_hint->setText(sourceText(QStringLiteral("选择已有项目并填写采样 UUID、目标 PID 和进程创建时间，设置来源与时长后开始采集。查看已保存的数据时，填写网络段号并点击“读取网络段”；段号 0 表示最新一段。")));
    m_browse->setText(sourceText(QStringLiteral("选择已有项目…")));
    m_browse->setToolTip(sourceText(QStringLiteral("选择已有分析项目；选择后点击采集或读取才会执行。")));

    // 输入保持原对象和内容；只更新其现有标签，长标签继续由原表单换行。
    const auto label = [this](QWidget* input, const QString& source) // 原标签的源文案映射。
    {
        auto* target = qobject_cast<QLabel*>(m_form->labelForField(input)); // 输入对应的原标签。
        if (target)
        {
            target->setText(sourceText(source));
        }
    };
    label(m_project, QStringLiteral("项目路径"));
    label(m_sample, QStringLiteral("已有采样 UUID"));
    label(m_pid, QStringLiteral("目标 PID"));
    label(m_creation, QStringLiteral("创建 FILETIME"));
    label(m_source, QStringLiteral("采集来源"));
    label(m_duration, QStringLiteral("采集时长"));
    label(m_ordinal, QStringLiteral("网络段号（0 为最新）"));
    label(m_sequence, QStringLiteral("记录序号（可选）"));

    // 来源标识保持原值；提示解释选择结果，不改变当前选项或冻结请求。
    m_source->setToolTip(sourceText(QStringLiteral("raw-socket 从网络接口抓包，不保证捕获本机回环流量；existing-wfp 读取已启用的 WFP 抓包，不自动切换来源。")));
    m_sequence->setToolTip(sourceText(QStringLiteral("留空显示前 256 条、每包 64 字节；指定序号读取该记录全部归档字节。")));
    m_capture->setText(sourceText(QStringLiteral("采集到原采样")));
    m_capture->setToolTip(sourceText(QStringLiteral("按当前参数采集目标进程的网络数据，保存到所填采样。")));
    m_read->setText(sourceText(QStringLiteral("读取网络段")));
    m_read->setToolTip(sourceText(QStringLiteral("读取已保存的网络数据；目标进程退出后仍可查看。")));
    m_cancel->setAccessibleName(sourceText(QStringLiteral("停止采集")));
    m_cancel->setToolTip(sourceText(QStringLiteral("停止本次采集并保存剩余数据，保留已保存的采样内容。")));

    // 页签与状态单独翻译，不重新发布字节正文或重置搜索与选择。
    m_tabs->setTabText(m_tabs->indexOf(m_fields), sourceText(QStringLiteral("采集与回读回执")));
    m_tabs->setTabText(m_tabs->indexOf(m_bytes), sourceText(QStringLiteral("网络字节")));
    m_status->setText(sourceText(m_statusSource));
}

// 原状态源文案不经过反向翻译，运行中、失败和完成状态均可往返切换语言。
void NetworkTrafficPane::setStatus(const QString& source)
{
    m_statusSource = source;
    m_status->setText(sourceText(m_statusSource));
}

// 接收应用语言事件，仅更新已存在的展示分支，不触发worker或读取项目。
void NetworkTrafficPane::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event->type() == QEvent::LanguageChange && m_tabs)
    {
        retranslate();
    }
}

// 页面销毁时先置取消位，再关闭回投门禁；worker仍持正式租约直至同步采集返回。
NetworkTrafficPane::~NetworkTrafficPane()
{
    if (m_cancelled) {
        m_cancelled->store(true);
    }
    m_worker->close();
}

// 选择manifest只形成草稿，不改写上次回执的项目或sample。
void NetworkTrafficPane::chooseProject()
{
    const auto path = QFileDialog::getOpenFileName(this, sourceText(QStringLiteral("选择已有项目…")),
        m_project->text(), QStringLiteral("ActionAnalyze (project.ksaproj)"));
    if (!path.isEmpty()) {
        m_project->setText(path);
    }
}

// 独立取消位只属于本次采集；读任务同样单个在途，不能替换已接受的写事务。
void NetworkTrafficPane::updateActions()
{
    const bool busy = m_worker && m_worker->isBusy(); // 原控制器的真实忙状态。
    m_capture->setEnabled(!busy);
    m_read->setEnabled(!busy);
    m_cancel->setEnabled(busy && m_cancelled && !m_cancelled->load());
}

// 严格按十进制解析并按值提交；运行中编辑草稿不会重定向已接受请求。
void NetworkTrafficPane::execute(bool capture)
{
    if (m_worker->isBusy()) {
        return;
    }
    project::NetworkTrafficRequest request; // 此刻唯一冻结的请求副本。
    request.capture = capture;
    request.projectPath = m_project->text().trimmed().toStdWString();
    request.plan.sampleId = m_sample->text().trimmed().toStdString();
    bool valid = !request.projectPath.empty() && project::ProjectStorage::IsUuid(request.plan.sampleId);
    const auto number = [&](QLineEdit* input, bool optional) {
        const auto text = input->text().trimmed(); // 不接受负数、符号、空白内嵌或部分数字。
        bool ok = optional && text.isEmpty();
        qulonglong value = 0;
        if (!text.isEmpty()) {
            ok = true;
            for (const auto ch : text) {
                ok = ok && ch >= QLatin1Char('0') && ch <= QLatin1Char('9');
            }
            bool parsed = false;
            value = text.toULongLong(&parsed, 10);
            ok = ok && parsed;
        }
        valid = valid && ok;
        return value;
    };
    if (capture) {
        const auto pid = number(m_pid, false); // UINT32_MAX不是有效目标。
        request.plan.creationFileTime = number(m_creation, false);
        valid = valid && pid > 0 && pid < (std::numeric_limits<std::uint32_t>::max)() && request.plan.creationFileTime;
        request.plan.pid = static_cast<std::uint32_t>(pid);
        request.plan.durationMs = static_cast<std::uint32_t>(m_duration->value());
        request.plan.backend = m_source->currentIndex() == 0 ? project::NetworkTrafficBackend::RawSocket :
            project::NetworkTrafficBackend::ExistingWfp;
    } else {
        request.ordinal = number(m_ordinal, false);
        request.recordSequence = number(m_sequence, true);
    }
    if (!valid) {
        setStatus(QStringLiteral("参数无效：请核对已有项目、采样 UUID，并用十进制填写 PID、创建时间或网络段号。"));
        return;
    }

    const auto cancelled = std::make_shared<std::atomic_bool>(false); // 不借用页面内存的取消位。
    m_cancelled = capture ? cancelled : nullptr;
    const auto ticket = m_worker->submitTransaction<project::NetworkTrafficRequest, NetworkTrafficView>(request,
        [cancelled](const auto& frozen) { return RunNetworkTraffic(frozen, *cancelled); },
        [this](const NetworkTrafficView& view, std::uint64_t) {
            m_fields->setDocument(view.fields);
            m_bytes->setRawText(view.bytes);
            m_cancelled.reset();
            const auto& result = view.result; // 成功空段与失败分开显示，详细阶段仍在回执内。
            const bool ok = result.opened && (result.request.capture ? result.receipt.status &&
                result.receipt.sourceReady && result.receipt.cleanupConfirmed && result.receipt.reason == "duration-elapsed" &&
                !result.receipt.queueDropped && !result.receipt.sourceGap && !result.receipt.unsupportedPackets &&
                result.receipt.checkpoint.ordinal && result.read.status : bool(result.read.status));
            if (ok && result.request.capture && !result.receipt.packets)
            {
                // 正常封段但未观察到报文，与失败、未就绪和存在报文分别显示。
                setStatus(QStringLiteral("采集已结束，未观察到目标报文；来源就绪不代表覆盖全部流量或本机回环。"));
            }
            else
            {
                setStatus(ok ? QStringLiteral("操作已结束，实际来源与结果见回执。") :
                    QStringLiteral("操作未完整完成，错误或部分结果见回执；可修正参数后重试。"));
            }
            return true;
        },
        [this](std::exception_ptr) {
            m_cancelled.reset();
            setStatus(QStringLiteral("后台操作异常；保留原结果，请检查项目后重试。"));
        });
    if (!ticket) {
        m_cancelled.reset();
        setStatus(QStringLiteral("后台操作未受理，请稍后重试。"));
    } else {
        setStatus(QStringLiteral("正在按本次参数执行；当前回执仍属于上次结果。"));
    }
    updateActions();
}

} // namespace ks::action_analyze
