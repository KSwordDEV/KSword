#include "../Framework.h"
#include "ExecutionGroupPage.h"
#include "ExecutionGroupFields.h"
#include "ExecutionGroupSiteEditor.h"
#include "PrivateExecutionRangePane.h"
#include "NativeSessionApiPane.h"
#include "../Framework/BackgroundTaskRegistry.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/ResultTableHost.h"
#include "../UI/ThemeStatusRole.h"

#include <QCheckBox>
#include <QGroupBox>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTimer>
#include <QUuid>
#include <algorithm>

namespace ks::action_analyze
{
    namespace native = execution_group_native;
    using ks::i18n::sourceText;

    // 输入all范围开关，返回点击时全部所选行；不从当前第一行推断批次。
    std::vector<int> ExecutionGroupPage::Selected(bool all) const
    {
        std::vector<int> rows; // 行号仅在GUI本次操作中定位冻结目录，不传给worker。
        if (all)
        {
            for (int row = 0; row < m_model->rowCount(); ++row)
            {
                rows.push_back(row);
            }
        }
        else
        {
            for (const auto& index : m_members->selectionModel()->selectedRows())
            {
                rows.push_back(index.row());
            }
            std::sort(rows.begin(), rows.end()); // 按冻结目录顺序提交显式子集。
        }
        return rows;
    }

    // 输入加入/替换语义，完整校验单站点再变更草稿；活集合始终不可重配置。
    void ExecutionGroupPage::AddSite(bool replace)
    {
        if (m_session || (!replace && m_model->sites.size() >= native::kOwnedExecutionGroupLimit))
        {
            return;
        }
        const auto selected = Selected(); // 替换必须是明确唯一行。
        if (replace && selected.size() != 1)
        {
            return;
        }
        native::ExecutionGroupSite site; // editor只有全字段和条件成功时才给出冻结值。
        if (m_editor->Prepare(site, m_inputError))
        {
            auto rows = m_model->sites; // 原草稿在失败时保持不变。
            const auto duplicate = std::find_if(rows.begin(), rows.end(), [&](const auto& existing)
            {
                return existing.pid == site.pid;
            });
            const bool sameRow = replace && duplicate != rows.end() && std::distance(rows.begin(), duplicate) == selected.front();
            if (duplicate != rows.end() && !sameRow)
            {
                m_inputError = sourceText(QStringLiteral("同一 PID 只能加入一个执行站点。"));
            }
            else
            {
                const int changedRow = replace ? selected.front() : static_cast<int>(rows.size()); // 修改后选中完整新站点。
                if (replace)
                {
                    rows.at(changedRow) = std::move(site);
                }
                else
                {
                    rows.push_back(std::move(site));
                }
                m_model->Replace(std::move(rows));
                m_members->selectRow(changedRow);
                m_inputError.clear();
            }
        }
        Render();
        Detail();
    }

    // 显式载入唯一选中草稿；不从实际断点绑定反推期望散列，不改变保存的目录。
    void ExecutionGroupPage::LoadSite()
    {
        const auto selected = Selected(); // 选择变化只展示详情，只有本动作会覆盖编辑表单。
        if (m_session || selected.size() != 1)
        {
            return;
        }
        m_editor->LoadDraft(m_model->sites.at(selected.front()));
        m_inputError.clear();
        Render();
    }

    // 移除未启动目录全部所选行，失败/活集合的原成员不会被删除以掩盖责任。
    void ExecutionGroupPage::RemoveSites()
    {
        if (m_session)
        {
            return;
        }
        const auto selected = Selected(); // 删除前冻结全部行，反向删除避免索引漂移。
        auto rows = m_model->sites;
        for (auto row = selected.rbegin(); row != selected.rend(); ++row)
        {
            rows.erase(rows.begin() + *row);
        }
        m_model->Replace(std::move(rows));
        m_inputError.clear();
        Render();
        Detail();
    }

    // 用户显式Start，冻结目录、授权和共同sampleId；所有原生owner在同一worker创建。
    void ExecutionGroupPage::Start()
    {
        if (!m_start->isEnabled())
        {
            return;
        }
        ExecutionGroupRequest request; // 不读取之后的参数框、选择或授权变化。
        request.command = ExecutionGroupCommand::Start;
        request.sites = m_model->sites;
        request.authorized = m_authorized->isChecked();
        request.sampleId = QUuid::createUuid().toString(QUuid::WithoutBraces).toStdString();
        request.projectDirectory = m_projectDirectory->text().toStdWString(); // 参数冻结后交原worker持唯一写租约。
        request.openExistingProject = m_openProject->isChecked();
        m_session = std::make_unique<ExecutionGroupSession>(); // 唯一本端会话，项目准备完成后才附加。
        m_shown = {};
        m_inputError = m_session->Submit(std::move(request)) ? QString() : sourceText(QStringLiteral("本端会话未受理操作，请刷新后重试。"));
        m_poll->start();
        Poll();
    }

    // 输入已解析范围，将唯一选中成员的完整当前停点按值交原worker；失败保留范围和站点草稿。
    void ExecutionGroupPage::AddRange(std::uint64_t address, std::uint64_t bytes)
    {
        if (!m_session || m_shown.busy || m_shown.closing || m_shown.retired)
        {
            return;
        }
        const auto selected = Selected(); // 只在点击当下定位单成员，不在worker中保存行索引。
        if (selected.size() != 1)
        {
            return;
        }
        const auto& site = m_model->sites.at(selected.front()); // PID和创建时间共同确定列表原成员。
        const auto member = std::find_if(m_shown.result.members.begin(), m_shown.result.members.end(), [&](const auto& item)
        {
            return item.site.pid == site.pid && item.site.creationFileTime == site.creationFileTime;
        });
        if (member == m_shown.result.members.end() || !native::OwnedExecutionGroup::CanAddRangeMember(*member))
        {
            return;
        }
        ExecutionGroupRequest request; // 独立AddRange动作，不复用Start也不提交Continue。
        request.command = ExecutionGroupCommand::AddRange;
        request.stops.push_back(member->control);
        request.rangeAddress = address;
        request.rangeBytes = bytes;
        m_inputError = m_session->Submit(std::move(request)) ? QString() : sourceText(QStringLiteral("本端会话未受理操作，请刷新后重试。"));
        Poll(); // 只投影已公布状态，不在GUI线程查询目标。
    }

    // 输入当前单选和来源草稿，输出冻结请求；模态确认期间清退或换集合后不派发旧请求。
    void ExecutionGroupPage::CaptureApi()
    {
        if (!m_captureApi->isEnabled() || !m_session)
        {
            return;
        }
        const auto rows = Selected(); // 参数确认前固定目标身份，确认后不会换成后来选择的成员。
        if (rows.size() != 1)
        {
            return;
        }
        const auto& site = m_model->sites.at(rows.front()); // 仅以强实例从显示回执定位原成员。
        const auto member = std::find_if(m_shown.result.members.begin(), m_shown.result.members.end(), [&](const auto& item) {
            return item.site.pid == site.pid && item.site.creationFileTime == site.creationFileTime;
        });
        if (member == m_shown.result.members.end())
        {
            return;
        }
        ExecutionGroupRequest request; // 所有输入值在显示确认前冻结，不向worker传控件。
        request.command = ExecutionGroupCommand::CaptureApi;
        request.sessions.push_back({member->owner, member->control});
        const auto collection = m_shown.result.collectionId; // 模态期间发生清退或新集合时拒绝旧请求。
        if (!m_apiPane->Prepare({member->control.pid, member->control.processCreationTime, member->control.attached}, request.api) ||
            !m_apiPane->Confirm(request.api))
        {
            return;
        }
        if (!m_session || m_shown.result.collectionId != collection || m_shown.closing || m_shown.retired)
        {
            return;
        }
        m_inputError = m_session->Submit(std::move(request)) ? QString() : sourceText(QStringLiteral("本端会话未受理操作，请刷新后重试。"));
        Poll(); // 实际owner/来源及全集排除由共享服务在原worker再核对。
    }

    // 输入动作和明确范围，复制当前显示的完整NativeControlResult vector；不重造stop token。
    void ExecutionGroupPage::Submit(ExecutionGroupCommand command, bool all, native::NativeStepMode mode)
    {
        if (!m_session || m_shown.busy || m_shown.closing || m_shown.retired)
        {
            return;
        }
        ExecutionGroupRequest request; // 所有控制依据点击时冻结值，后台不借控件。
        request.command = command;
        request.all = all;
        request.mode = mode;
        if (command != ExecutionGroupCommand::Query)
        {
            const auto selected = Selected(all); // Continue接受全集/明确子集；Step和Cancel只接受唯一成员。
            if (selected.empty() || ((command == ExecutionGroupCommand::Step || command == ExecutionGroupCommand::CancelStep ||
                command == ExecutionGroupCommand::SaveExecution) && selected.size() != 1))
            {
                return;
            }
            for (const auto row : selected)
            {
                const auto& site = m_model->sites.at(row); // 完整身份定位，不单独凭PID或TID授控制权。
                const auto member = std::find_if(m_shown.result.members.begin(), m_shown.result.members.end(), [&](const auto& item)
                {
                    return item.site.pid == site.pid && item.site.creationFileTime == site.creationFileTime;
                });
                if (member == m_shown.result.members.end())
                {
                    return; // 不从历史或站点草稿重建缺失成员的活会话。
                }
                bool eligible = ExecutionGroupCanRelease(*member); // 普通步进仍只接当前可控停点。
                if (command == ExecutionGroupCommand::Pause)
                {
                    eligible = native::OwnedExecutionGroup::CanPauseMember(*member);
                }
                else if (command == ExecutionGroupCommand::Continue)
                {
                    eligible = native::OwnedExecutionGroup::CanContinueMember(*member);
                }
                else if (command == ExecutionGroupCommand::CancelStep)
                {
                    eligible = native::OwnedExecutionGroup::MatchesStep(member->control, member->control);
                }
                else if (command == ExecutionGroupCommand::SaveExecution)
                {
                    eligible = m_shown.archive.writerHeld && native::NativeExecutionFromOwnedStop(member->control).has_value();
                }
                else if (command == ExecutionGroupCommand::Step && member->control.stopReason == native::NativeStopReason::ManualPause)
                {
                    eligible = false; // 手动暂停不借用原执行命中或旧step的步进资格。
                }
                if (!eligible)
                {
                    return; // 任一无资格不提交整批，已复制的临时vector不产生副作用。
                }
                if (command == ExecutionGroupCommand::Pause || command == ExecutionGroupCommand::Continue ||
                    command == ExecutionGroupCommand::SaveExecution)
                {
                    request.sessions.push_back({member->owner, member->control}); // 完整owner和显示快照，不从PID补票。
                }
                else
                {
                    request.stops.push_back(member->control); // Step/Cancel保留原完整事件、线程、修订和步进请求。
                }
            }
        }
        m_inputError = m_session->Submit(std::move(request)) ? QString() : sourceText(QStringLiteral("本端会话未受理操作，请刷新后重试。"));
        Poll();
    }

    // GUI只读取已公布状态；原后台250ms单在途Query处理条件并保留原始操作回执。
    void ExecutionGroupPage::Poll()
    {
        if (!m_session)
        {
            return;
        }
        m_session->SetCpuToken(ks::ui::BackgroundTaskRegistry::instance().cpuToken(
            QStringLiteral("monitor.action_analyze.execution_group"))); // 原任务计量身份传给下一轮worker，不复制采样器。
        const auto snapshot = m_session->Read(); // 不枚举进程、不查询原生所有者。
        const bool changed = snapshot.revision != m_shown.revision;
        m_shown = snapshot;
        if (changed)
        {
            m_model->Apply(snapshot.result); // 固定目录只更新数据，不重置选择。
            Detail();
        }
        Render();
        if (snapshot.retired)
        {
            m_poll->stop(); // 仅原Close clean后停止投影，未决责任不能因隐藏页面消失。
        }
    }

    // 依据同一显示快照计算全部所选资格；无资格时原生诊断和条件字段提供原因。
    void ExecutionGroupPage::Render()
    {
        const bool editable = !m_session; // 清退结束仍展示旧结果，显式返回草稿才允许变更。
        const bool ready = m_session && !m_shown.busy && !m_shown.closing && !m_shown.retired;
        const auto selected = Selected(); // 所有资格按完整多选范围评估。
        const auto release = [&](const std::vector<int>& rows)
        {
            return !rows.empty() && std::all_of(rows.begin(), rows.end(), [&](int row)
            {
                const auto& site = m_model->sites.at(row);
                return std::any_of(m_shown.result.members.begin(), m_shown.result.members.end(), [&](const auto& member)
                {
                    return member.site.pid == site.pid && member.site.creationFileTime == site.creationFileTime &&
                        native::OwnedExecutionGroup::CanContinueMember(member);
                });
            });
        };
        bool cancellable = false; // 取消针对原步进请求，不能用当前普通停点替代。
        bool stepAllowed = false; // 手动暂停只允许Continue，本批不开放ManualPause步进。
        bool rangeAllowed = false; // 完整NX Held支持独立追加，ManualPause无需步进资格。
        bool saveAllowed = false; // 执行事件保存与Continue资格分开，ManualPause没有执行证据。
        bool apiAllowed = false; // 来源采集不依赖精确停点，必须有本轮writer和仍附加的原成员。
        QString rangeTarget; // 明确当前追加目标；未单选时不沿用上一成员身份。
        if (selected.size() == 1)
        {
            const auto& site = m_model->sites.at(selected.front());
            cancellable = std::any_of(m_shown.result.members.begin(), m_shown.result.members.end(), [&](const auto& member)
            {
                return member.site.pid == site.pid && member.site.creationFileTime == site.creationFileTime &&
                    native::OwnedExecutionGroup::MatchesStep(member.control, member.control);
            });
            stepAllowed = std::any_of(m_shown.result.members.begin(), m_shown.result.members.end(), [&](const auto& member)
            {
                return member.site.pid == site.pid && member.site.creationFileTime == site.creationFileTime &&
                    member.control.stopReason != native::NativeStopReason::ManualPause && ExecutionGroupCanRelease(member);
            });
            const auto member = std::find_if(m_shown.result.members.begin(), m_shown.result.members.end(), [&](const auto& item)
            {
                return item.site.pid == site.pid && item.site.creationFileTime == site.creationFileTime;
            });
            if (member != m_shown.result.members.end())
            {
                rangeAllowed = native::OwnedExecutionGroup::CanAddRangeMember(*member);
                saveAllowed = m_shown.archive.writerHeld && native::NativeExecutionFromOwnedStop(member->control).has_value();
                apiAllowed = m_shown.archive.writerHeld && member->control.attached;
                rangeTarget = sourceText(QStringLiteral("追加目标：PID %1 / 创建 FILETIME %2 / 停点 %3"))
                    .arg(site.pid).arg(site.creationFileTime)
                    .arg(member->control.responsibility ? QString::fromStdString(member->control.responsibility->stopId) : QStringLiteral("—"));
            }
        }
        const auto pause = [&](const std::vector<int>& rows) // 主动暂停核对活执行绑定，不要求旧stop。
        {
            return !rows.empty() && std::all_of(rows.begin(), rows.end(), [&](int row)
            {
                const auto& site = m_model->sites.at(row);
                return std::any_of(m_shown.result.members.begin(), m_shown.result.members.end(), [&](const auto& member)
                {
                    return member.site.pid == site.pid && member.site.creationFileTime == site.creationFileTime &&
                        native::OwnedExecutionGroup::CanPauseMember(member);
                });
            });
        };
        m_editor->setEnabled(editable); // 活集合目录和条件不可被参数编辑静默重配。
        m_projectSection->setEnabled(editable); // 目录编辑不重定向已产生的结果或writer。
        m_authorized->setEnabled(editable);
        m_add->setEnabled(editable && m_model->sites.size() < native::kOwnedExecutionGroupLimit);
        m_replace->setEnabled(editable && selected.size() == 1);
        m_load->setEnabled(editable && selected.size() == 1);
        m_remove->setEnabled(editable && !selected.empty());
        m_start->setEnabled(m_registered && editable && !m_model->sites.empty() && m_authorized->isChecked());
        m_newDraft->setEnabled(m_session && m_shown.retired);
        m_pauseAll->setEnabled(ready && pause(Selected(true)));
        m_pauseSelected->setEnabled(ready && pause(selected));
        m_continueAll->setEnabled(ready && release(Selected(true)));
        m_continueSelected->setEnabled(ready && release(selected));
        for (auto* button : {m_into, m_over, m_out})
        {
            button->setEnabled(ready && stepAllowed);
        }
        m_cancel->setEnabled(ready && cancellable);
        m_save->setEnabled(ready && saveAllowed); // 允许同事件重放，原归档器返回旧段坐标不重复写。
        m_captureApi->setEnabled(ready && apiAllowed);
        m_apiPane->setEnabled(ready && apiAllowed); // 编辑仅形成草稿，不改写旧采集来源。
        m_query->setEnabled(ready);
        m_close->setEnabled(m_session && !m_shown.retired); // 在途动作时仍允许请求清退。
        m_rangeTarget->setVisible(m_session && !m_shown.retired);
        m_rangeTarget->setText(rangeTarget);
        m_rangePane->setVisible(m_session && !m_shown.retired);
        m_rangePane->SetAvailable(ready && rangeAllowed,
            ready && rangeAllowed ? QString() : sourceText(QStringLiteral("请选择一个持有完整 NX 停点的成员；追加操作不继续目标。")));
        QString status = ExecutionGroupStateText(m_shown.result.state); // 状态依据完整组，未回读不显示成功。
        if (m_session && !m_shown.revision)
        {
            status = sourceText(QStringLiteral("正在等待成员回执"));
        }
        if (m_shown.observedFileTime)
        {
            status += sourceText(QStringLiteral(" · 回读 FILETIME %1")).arg(m_shown.observedFileTime);
        }
        if (m_shown.busy)
        {
            status += sourceText(QStringLiteral(" · 操作进行中"));
        }
        if (m_shown.closing && !m_shown.retired)
        {
            status += sourceText(QStringLiteral(" · 原所有者清退未确认，保留恢复责任"));
        }
        if (m_shown.result.operation)
        {
            const auto& operation = *m_shown.result.operation; // 组准入不冒充全部成员成功。
            status += QStringLiteral(" / %1 / Win32 %2").arg(QString::fromLatin1(operation.stage)).arg(operation.win32Error);
        }
        if (m_shown.failed)
        {
            status += sourceText(QStringLiteral(" · 后台执行失败，保留上次回执")) + QStringLiteral(" / ") + QString::fromStdString(m_shown.diagnostic);
        }
        if (!m_shown.archive.setup || (m_shown.archive.saved && !m_shown.archive.saved->status))
        {
            const auto& failure = !m_shown.archive.setup ? m_shown.archive.setup : m_shown.archive.saved->status; // 存储失败不冒充控制失败。
            status += QLatin1Char('\n') + sourceText(QStringLiteral("执行观察归档")) + QStringLiteral(" / %1 / Win32 %2")
                .arg(QString::fromLatin1(failure.detail)).arg(failure.nativeError);
        }
        if (!m_registered)
        {
            status += sourceText(QStringLiteral(" · 后台所有者登记冲突"));
        }
        if (!m_inputError.isEmpty())
        {
            status += QLatin1Char('\n') + m_inputError;
        }
        m_status->setText(status);
        ks::ui::ApplyStatusRole(m_status, m_shown.failed || (m_shown.result.operation && m_shown.result.operation->win32Error)
            ? ks::ui::StatusRole::Error : ks::ui::StatusRole::Info);
    }

    void ExecutionGroupPage::Detail()
    {
        m_fields->setDocument(ExecutionGroupDocument(m_shown, m_model->sites, Selected())); // 搜索、复制和导出共享完整规范字段。
    }
}
