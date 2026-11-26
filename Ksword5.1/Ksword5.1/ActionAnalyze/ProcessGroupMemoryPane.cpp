#include "../Framework.h"
#include "ProcessGroupMemoryPane.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/FlowLayout.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/SecondaryPageLayout.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/ToolbarMetrics.h"

#include <QFileDialog>
#include <QComboBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QUuid>
#include <QVBoxLayout>
#include <algorithm>
#include <limits>

namespace ks::action_analyze
{
    namespace native = process_group_native;
    namespace memory = ks::cli::action_analyze::memory;
    using ks::i18n::sourceText;

    ProcessGroupMemoryPane::ProcessGroupMemoryPane(QWidget* parent, bool nativeStop) : QWidget(parent)
    {
        auto* root = new QVBoxLayout(this); // 参数区内组合，不增加页根留白。
        root->setContentsMargins(0, 0, 0, 0);
        auto* section = new QGroupBox(this); // 同类参数共享分区皮肤。
        auto* form = new QFormLayout(section); // 自然高度及窄栏折行。
        ks::ui::StyleSecondaryForm(form, 100);
        ks::i18n::LanguageManager::instance().bindText(section, {}, QStringLiteral("选中范围只读快照"));
        m_directory = new QLineEdit(section);
        m_base = new QLineEdit(section);
        m_bytes = new QLineEdit(section);
        m_directory->setObjectName(QStringLiteral("action_analyze_group_memory_project"));
        m_base->setObjectName(QStringLiteral("action_analyze_group_memory_base"));
        m_bytes->setObjectName(QStringLiteral("action_analyze_group_memory_bytes"));
        m_base->setMaxLength(20);
        m_bytes->setMaxLength(20);
        const auto field = [&](QLineEdit* input, const QString& title) {
            auto* label = new QLabel(section); // 标签绑定同一输入，语言切换不丢草稿。
            label->setBuddy(input);
            ks::i18n::LanguageManager::instance().bindText(label, {}, title);
            form->addRow(label, input);
        };
        if (nativeStop)
        {
            m_projectMode = new QComboBox(section); // 打开已有项目必须显式选择，不根据目录存在性静默切换。
            m_projectMode->setObjectName(QStringLiteral("action_analyze_native_project_mode"));
            m_projectMode->addItem(sourceText(QStringLiteral("新建项目")), false);
            m_projectMode->addItem(sourceText(QStringLiteral("打开项目并新建采样")), true);
            auto* modeLabel = new QLabel(section); // 与实际组合框配对，参数正文自然高度。
            modeLabel->setBuddy(m_projectMode);
            ks::i18n::LanguageManager::instance().bindText(modeLabel, {}, QStringLiteral("归档项目方式"));
            form->addRow(modeLabel, m_projectMode);
        }
        field(m_directory, nativeStop ? QStringLiteral("归档项目目录（可选）") : QStringLiteral("新项目目录（可选）"));
        field(m_base, QStringLiteral("起始地址（0x 或十进制）"));
        field(m_bytes, QStringLiteral("范围字节数"));
        m_error = new QLabel(section); // 输入错误与既有结果独立。
        m_error->setWordWrap(true);
        ks::ui::ApplyStatusRole(m_error, ks::ui::StatusRole::Error);
        form->addRow(m_error);
        auto* hint = new QLabel(section); // 明确逐页采样与前置保存目录，不宣称完整进程dump。
        hint->setWordWrap(true);
        ks::i18n::LanguageManager::instance().bindText(hint, {}, nativeStop
            ? QStringLiteral("完整原生停点下读取所选范围，保存实际成功页。启动前可新建项目，或打开已有项目并新建采样；已有项目占用时不会另开写入会话。逐页读取不是原子进程转储。")
            : QStringLiteral("仅在选中成员持有完整原生停点时读取所选范围，失败不转为实时读取。逐页取样不是原子进程转储。配置前可选全新项目目录，保存仅写实际成功页。"));
        form->addRow(hint);
        ks::ui::StyleParameterSection(section);
        root->addWidget(section);
        auto* actions = new QWidget(this); // 局部显式动作自动换行。
        auto* flow = new ks::ui::FlowLayout(actions, 0, 8, 8);
        const auto action = [&](const QString& title, const QString& tooltip) {
            auto* button = new QPushButton(actions); // 标准主题自动拥有基本外观。
            ks::i18n::LanguageManager::instance().bindText(button, {}, title);
            ks::i18n::LanguageManager::instance().bindToolTip(button, {}, tooltip);
            flow->addWidget(button);
            return button;
        };
        m_browse = action(QStringLiteral("选择新项目目录"), QStringLiteral("只选择尚不存在的目录；配置或启动前创建本端独立项目与采样。"));
        if (nativeStop)
        {
            ks::i18n::LanguageManager::instance().bindText(m_browse, {}, QStringLiteral("选择归档项目目录"));
            ks::i18n::LanguageManager::instance().bindToolTip(m_browse, {}, QStringLiteral("按所选方式选择新目录或已有项目目录；启动时才取得写入会话并创建本次采样。"));
        }
        m_read = action(nativeStop ? QStringLiteral("读取停点内存") : QStringLiteral("读取选中停点内存"),
            QStringLiteral("冻结目标、起点、长度和完整停点令牌，在原串行控制器执行只读采样。"));
        m_save = action(QStringLiteral("保存本次内存快照"), QStringLiteral("将当前实际读取的成功页和失败元数据写入本端采样 raw-memory，不补零。"));
        m_read->setObjectName(QStringLiteral("action_analyze_group_memory_read"));
        m_save->setObjectName(QStringLiteral("action_analyze_group_memory_save"));
        ks::ui::NormalizeToolbarLayout(flow);
        root->addWidget(actions);
        connect(m_browse, &QPushButton::clicked, this, [this] {
            const auto directory = OpenExistingProject()
                ? QFileDialog::getExistingDirectory(this, sourceText(QStringLiteral("选择已有行为分析项目目录")), m_directory->text())
                : QFileDialog::getSaveFileName(this,
                    sourceText(QStringLiteral("输入全新内存快照项目目录")), m_directory->text(), {}, nullptr,
                    QFileDialog::DontConfirmOverwrite); // 取消不改变草稿，新建模式仍拒绝已有目录。
            if (!directory.isEmpty()) m_directory->setText(directory);
        });
        connect(m_read, &QPushButton::clicked, this, [this] { if (execute) execute(false); });
        connect(m_save, &QPushButton::clicked, this, [this] { if (execute) execute(true); });
    }

    std::wstring ProcessGroupMemoryPane::ProjectDirectory() const
    {
        return m_directory->text().trimmed().toStdWString(); // 不对已经创建的项目静默换目录。
    }

    // 输入当前模式草稿，输出是否明确打开已有项目；不读取目录或取得写租约。
    bool ProcessGroupMemoryPane::OpenExistingProject() const
    {
        return m_projectMode && m_projectMode->currentData().toBool();
    }

    void ProcessGroupMemoryPane::MoveExecutionActions(QLayout* actions)
    {
        for (auto* button : {m_read, m_save}) // 只移动显式执行动作；新目录选择仍属于参数草稿。
        {
            button->parentWidget()->layout()->removeWidget(button);
            button->setParent(actions->parentWidget());
            actions->addWidget(button);
        }
    }

    bool ProcessGroupMemoryPane::Prepare(const ProcessGroupSessionSnapshot& shown,
        const native::ProcessGroupTarget& target, ProcessGroupRequest& request)
    {
        bool baseValid = false, sizeValid = false; // 不接受空范围或溢出地址。
        const auto text = m_base->text().trimmed(); // 明确0x选择十六进制，其余十进制。
        const auto base = text.toULongLong(&baseValid, text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) ? 16 : 10);
        const auto bytes = m_bytes->text().trimmed().toULongLong(&sizeValid, 10);
        const auto member = std::find_if(shown.result.members.begin(), shown.result.members.end(), [&](const auto& item) { return item.target == target; });
        if (!baseValid || !sizeValid || !base || !bytes || bytes > (std::numeric_limits<std::uint64_t>::max)() - base ||
            member == shown.result.members.end() || !member->stop || !member->control || !member->control->group ||
            member->control->group->state != native::GroupState::HeldComplete)
        {
            m_error->setText(sourceText(QStringLiteral("请输入有效非零范围，并选择一个持有完整原生停点的成员。")));
            return false;
        }
        native::ProcessMemorySnapshotRequest capture; // 全部字段来自点击时的冻结身份。
        capture.source = native::ProcessMemorySource::HeldEvent;
        capture.stop = *member->stop;
        capture.plan.sampleId = member->control->group->sampleId;
        capture.plan.trackingEpoch = QUuid::createUuid().toString(QUuid::WithoutBraces).toStdString();
        capture.plan.target = {member->control->group->sessionId, member->control->group->epoch,
            member->control->processInstanceId, target.pid, target.creationFileTime}; // machine/boot仅会话局部标签。
        capture.plan.range = {base, bytes};
        capture.plan.rounds = 2; // 共享Plan要求至少两轮；单次CaptureSelectedMemory只取首轮后Stop。
        capture.plan.authorizedOwnedProcess = true; // 仅配置时明确授权的精确成员可以到达此处。
        request.command = ProcessGroupCommand::ReadMemory;
        request.memory = std::move(capture);
        m_error->clear();
        return true;
    }

    bool ProcessGroupMemoryPane::PrepareNative(const native::NativeControlResult& displayed, ProcessGroupRequest& request)
    {
        ProcessGroupSessionSnapshot view; // 仅复用参数校验，不创建集合或第二个原生所有者。
        native::ProcessGroupMember member; // 身份与完整令牌均来自用户实际显示的原回执。
        member.target = {displayed.pid, displayed.processCreationTime};
        member.control = displayed;
        if (displayed.responsibility && displayed.group)
        {
            const auto& stop = *displayed.responsibility; // 后台CaptureMemory仍核对sample/session/epoch。
            member.stop = native::ProcessGroupStop{member.target, stop.groupId, stop.stopId,
                stop.event, displayed.group->stateRevision};
        }
        view.result.members.push_back(member);
        return Prepare(view, member.target, request);
    }

    void ProcessGroupMemoryPane::Update(const ProcessGroupSessionSnapshot& shown, bool oneSelected, bool configured)
    {
        m_directory->setEnabled(!configured); // 项目创建前可编辑；活会话路径只读冻结。
        if (m_projectMode)
        {
            m_projectMode->setEnabled(!configured);
            m_projectMode->setItemText(0, sourceText(QStringLiteral("新建项目")));
            m_projectMode->setItemText(1, sourceText(QStringLiteral("打开项目并新建采样")));
        }
        m_browse->setEnabled(!configured);
        m_read->setEnabled(configured && oneSelected && !shown.busy && !shown.closing && !shown.retired);
        m_save->setEnabled(configured && !shown.busy && !shown.closing && !shown.retired &&
            !shown.memoryArchiveBlocked && !shown.projectDirectory.empty() && shown.memory && shown.memory->snapshot &&
            shown.memory->snapshot->round && !shown.memory->snapshot->round->pages.empty());
    }

    void ProcessGroupMemoryPane::Append(ks::ui::FieldDocument& document, const ProcessGroupSessionSnapshot& shown)
    {
        if (!shown.projectDirectory.empty() || !shown.projectResult)
        {
            document.section(QStringLiteral("本端内存快照项目"))
                .field(QStringLiteral("项目路径"), QString::fromStdWString(shown.projectDirectory))
                .field(QStringLiteral("采样 ID"), QString::fromStdString(shown.sampleId))
                .field(QStringLiteral("项目结果"), QString::fromLatin1(shown.projectResult.detail))
                .field(QStringLiteral("Win32 错误"), QString::number(shown.projectResult.nativeError));
        }
        if (shown.memoryArchiveBlocked)
        {
            document.note(QStringLiteral("原内存段写入或回读失败，已保留现场并停止追加。清退后可显式选择新项目。"));
        }
        if (shown.memoryArchive)
        {
            const auto& receipt = *shown.memoryArchive; // 无新快照时也保留原失败段的坐标与来源。
            document.section(QStringLiteral("内存归档回执"));
            if (shown.memoryArchiveSource)
            {
                const auto& plan = shown.memoryArchiveSource->request.plan; // 原保存请求与最新读取分别保留。
                document.field(QStringLiteral("PID"), QString::number(plan.target.pid))
                    .field(QStringLiteral("创建 FILETIME"), QString::number(plan.target.creationFileTime100ns))
                    .field(QStringLiteral("范围起点"), QStringLiteral("0x%1").arg(plan.range.base, 0, 16))
                    .field(QStringLiteral("范围字节数"), QString::number(plan.range.length));
            }
            document.field(QStringLiteral("raw-memory 段号"), QString::number(receipt.ordinal))
                .field(QStringLiteral("实际归档字节数"), QString::number(receipt.capturedBytes))
                .field(QStringLiteral("失败页数"), QString::number(receipt.unavailablePages))
                .field(QStringLiteral("同步回读核验"), receipt.verified ? QStringLiteral("是") : QStringLiteral("否"), true)
                .field(QStringLiteral("SHA-256"), QString::fromStdString(receipt.sha256));
            for (const auto* boundary : {&receipt.raw.written, &receipt.raw.flushed})
            {
                document.field(boundary == &receipt.raw.written ? QStringLiteral("内存写入坐标") : QStringLiteral("内存刷盘坐标"),
                    *boundary ? QStringLiteral("%1 / %2 / %3").arg((*boundary)->byteOffset)
                        .arg((*boundary)->blockOrdinal).arg((*boundary)->lastSequence) : QStringLiteral("未取得"));
            }
        }
        if (!shown.memory) return;
        const auto& read = *shown.memory; // 结果保持读取时的精确请求，不借用当前输入草稿。
        document.section(QStringLiteral("本次选中范围内存"))
            .field(QStringLiteral("PID"), QString::number(read.request.plan.target.pid))
            .field(QStringLiteral("创建 FILETIME"), QString::number(read.request.plan.target.creationFileTime100ns))
            .field(QStringLiteral("范围起点"), QStringLiteral("0x%1").arg(read.request.plan.range.base, 0, 16))
            .field(QStringLiteral("范围字节数"), QString::number(read.request.plan.range.length))
            .field(QStringLiteral("采样 ID"), QString::fromStdString(read.request.plan.sampleId))
            .field(QStringLiteral("读取来源"), read.request.source == native::ProcessMemorySource::HeldEvent
                ? QStringLiteral("HeldEvent") : QStringLiteral("LiveRead"))
            .field(QStringLiteral("原生诊断"), QString::fromLatin1(read.stage))
            .field(QStringLiteral("Win32 错误"), QString::number(read.win32Error))
            .field(QStringLiteral("读取前后同一停点"), read.heldAtBothChecks ? QStringLiteral("是") : QStringLiteral("否"), true);
        for (const auto* stop : {&read.before, &read.after}) // 展示真实前后完整身份，不由当前成员选择重建。
        {
            document.section(stop == &read.before ? QStringLiteral("读取前停点") : QStringLiteral("读取后停点"));
            if (*stop)
            {
                document.field(QStringLiteral("停止组 ID"), QString::fromStdString((*stop)->groupId))
                    .field(QStringLiteral("停点 ID"), QString::fromStdString((*stop)->stopId))
                    .field(QStringLiteral("后端实例 ID"), QString::fromStdString((*stop)->event.backendInstanceId))
                    .field(QStringLiteral("原生事件序号"), QString::number((*stop)->event.serial))
                    .field(QStringLiteral("状态修订"), QString::number((*stop)->stateRevision));
            }
            else
            {
                document.field(QStringLiteral("停点 ID"), QStringLiteral("未取得"), true);
            }
        }
        if (!read.snapshot) return;
        const auto& snapshot = *read.snapshot; // 成功页原字节仅在此快照中存在，失败无补零。
        const auto state = snapshot.status.state; // 拒绝、失败、取消和已采样结果必须能区分。
        const auto stateText = state == memory::State::Stopped ? QStringLiteral("采样已停止")
            : state == memory::State::Rejected ? QStringLiteral("采样被拒绝")
            : state == memory::State::Failed ? QStringLiteral("采样失败")
            : state == memory::State::Canceled ? QStringLiteral("采样已取消")
            : state == memory::State::TargetExited ? QStringLiteral("采样目标已退出")
            : state == memory::State::Completed ? QStringLiteral("采样已完成")
            : state == memory::State::Active ? QStringLiteral("采样进行中") : QStringLiteral("采样尚未开始");
        const auto visited = snapshot.round ? snapshot.round->pages.size() : 0; // 取消前尚未访问的页不冒充读取失败。
        document.section(QStringLiteral("采样器状态"))
            .field(QStringLiteral("采样状态"), stateText, true)
            .field(QStringLiteral("采样诊断阶段码"), QString::number(static_cast<int>(snapshot.status.issue.stage)))
            .field(QStringLiteral("Win32 错误"), QString::number(snapshot.status.issue.win32Error))
            .field(QStringLiteral("计划页数"), QString::number(snapshot.status.plannedPages))
            .field(QStringLiteral("已访问页数"), QString::number(visited))
            .field(QStringLiteral("未访问页数"), QString::number(snapshot.status.plannedPages > visited
                ? snapshot.status.plannedPages - visited : 0));
        if (snapshot.status.issue.ntStatus)
        {
            document.field(QStringLiteral("NTSTATUS"), QStringLiteral("0x%1")
                .arg(static_cast<std::uint32_t>(*snapshot.status.issue.ntStatus), 8, 16, QLatin1Char('0')));
        }
        std::uint64_t capturedBytes = 0; // 真实成功字节总和。
        for (const auto& page : snapshot.captured) capturedBytes += page.bytes.size();
        document.field(QStringLiteral("成功页数"), QString::number(snapshot.captured.size()))
            .field(QStringLiteral("失败页数"), QString::number(snapshot.status.unavailablePages))
            .field(QStringLiteral("实际读取字节数"), QString::number(capturedBytes))
            .field(QStringLiteral("所选范围完整"), snapshot.completeRange ? QStringLiteral("是") : QStringLiteral("否"), true)
            .field(QStringLiteral("QPC 频率"), QString::number(snapshot.status.qpcFrequency));
        if (snapshot.round)
        {
            document.field(QStringLiteral("采样开始 QPC"), QString::number(snapshot.round->beginQpc))
                .field(QStringLiteral("采样结束 QPC"), snapshot.round->endQpc ? QString::number(*snapshot.round->endQpc) : QString());
            for (const auto& page : snapshot.round->pages)
            {
                document.section(QStringLiteral("采样页 %1").arg(page.pageBase, 0, 16))
                    .field(QStringLiteral("页状态码"), QString::number(static_cast<int>(page.status)))
                    .field(QStringLiteral("Win32 错误"), QString::number(page.issue.win32Error))
                    .field(QStringLiteral("范围字节数"), QString::number(page.sampledRange.length));
                if (page.readQpc)
                {
                    document.field(QStringLiteral("页面读取 QPC"), QStringLiteral("%1 / %2")
                        .arg(page.readQpc->begin).arg(page.readQpc->end));
                }
            }
        }
        for (const auto& page : snapshot.captured)
        {
            const auto previewBytes = (std::min)(std::size_t{256}, page.bytes.size()); // 有界预览，完整原字节仍可归档。
            const QByteArray bytes(reinterpret_cast<const char*>(page.bytes.data()), static_cast<qsizetype>(previewBytes));
            document.section(QStringLiteral("成功页字节 %1").arg(page.observation.sampledRange.base, 0, 16))
                .field(QStringLiteral("实际读取字节数"), QString::number(page.bytes.size()))
                .field(QStringLiteral("前 256 字节预览"), QString::fromLatin1(bytes.toHex(' ')));
        }
    }
}
