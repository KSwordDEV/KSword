#include "../Framework.h"
#include "OfflineSegmentOverview.h"
#include "DataWriteWatchPage.h"
#include "ProcessGroupPage.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/FlowLayout.h"
#include "../UI/ThemeAccentIcon.h"
#include "../UI/ToolbarMetrics.h"
#include "../theme.h"

#include <QPointer>
#include <QPushButton>
#include <array>

namespace ks::action_analyze
{
    namespace
    {
        using ks::i18n::sourceText;
        struct NativeActionEntry
        {
            DataWatchToolbarAction action; // 固定原生操作，不依赖按钮索引或翻译文本。
            const char* name; // 稳定对象名，供工具条查找当前动作。
            const char* icon; // 项目主题SVG资源。
            QString text; // 使用QStringLiteral登记可翻译的动作名称。
        };
        const std::array kNativeActions{
            NativeActionEntry{DataWatchToolbarAction::Pause, "action_analyze_native_pause", ":/Icon/process_suspend.svg", QStringLiteral("主动暂停原执行会话")},
            NativeActionEntry{DataWatchToolbarAction::Continue, "action_analyze_native_continue", ":/Icon/process_resume.svg", QStringLiteral("继续原生停点")},
            NativeActionEntry{DataWatchToolbarAction::OverCall, "action_analyze_native_over", ":/Icon/action_analyze_step_over.svg", QStringLiteral("逐过程（机器指令步过）")},
            NativeActionEntry{DataWatchToolbarAction::Into, "action_analyze_native_into", ":/Icon/action_analyze_step_into.svg", QStringLiteral("逐语句（机器指令步入）")},
            NativeActionEntry{DataWatchToolbarAction::Out, "action_analyze_native_out", ":/Icon/action_analyze_step_out.svg", QStringLiteral("跳出可信调用帧")},
            NativeActionEntry{DataWatchToolbarAction::CancelStep, "action_analyze_native_cancel_step", ":/Icon/action_analyze_cancel_step.svg", QStringLiteral("取消原生步进")},
            NativeActionEntry{DataWatchToolbarAction::DumpMemory, "action_analyze_native_memory_dump", ":/Icon/action_analyze_memory_dump.svg", QStringLiteral("转储当前停点内存范围")},
            NativeActionEntry{DataWatchToolbarAction::Close, "action_analyze_native_detach", ":/Icon/process_stop.svg", QStringLiteral("脱离写入／执行监控")}
        };
        struct GroupActionEntry
        {
            ProcessGroupToolbarAction action; // 与原集合页按钮一一对应。
            const char* name; // 稳定对象名。
            const char* icon; // 统一主题资源。
            QString text; // 动作明确说明全集或原集合表选区。
        };
        const std::array kGroupActions{
            GroupActionEntry{ProcessGroupToolbarAction::PauseAll, "action_analyze_global_pause", ":/Icon/process_suspend.svg", QStringLiteral("全局暂停（本集合）")},
            GroupActionEntry{ProcessGroupToolbarAction::ContinueAll, "action_analyze_global_continue", ":/Icon/process_resume.svg", QStringLiteral("全局继续（本集合）")},
            GroupActionEntry{ProcessGroupToolbarAction::PauseSelected, "action_analyze_selected_pause", ":/Icon/process_suspend.svg", QStringLiteral("暂停集合选中成员")},
            GroupActionEntry{ProcessGroupToolbarAction::ContinueSelected, "action_analyze_selected_continue", ":/Icon/process_resume.svg", QStringLiteral("继续集合选中成员")},
            GroupActionEntry{ProcessGroupToolbarAction::Recover, "action_analyze_group_recover", ":/Icon/process_refresh.svg", QStringLiteral("重试原集合继续票据")},
            GroupActionEntry{ProcessGroupToolbarAction::Close, "action_analyze_group_detach", ":/Icon/process_stop.svg", QStringLiteral("清退本集合原生控制")}
        };
    }

    // 输入原页面端口，在现有可浮出工具条加入实际动作，保持原按钮与停点所有权。
    void OfflineSegmentOverview::setNativeWatchToolbar(std::shared_ptr<DataWatchToolbarPort> toolbar)
    {
        if (m_nativeWatch || !toolbar)
        {
            return;
        }
        m_nativeWatch = std::move(toolbar);
        auto* actions = static_cast<ks::ui::FlowLayout*>(m_actionStrip->layout()); // 复用原动作带的窄窗换行。
        for (const auto& entry : kNativeActions)
        {
            auto* button = new QPushButton(m_actionStrip); // 只创建UI动作，原owner位于写入停点页。
            button->setObjectName(QString::fromLatin1(entry.name));
            KswordTheme::ApplyStandardIconButtonMetrics(button);
            ks::ui::SetThemeButtonIcon(button, QIcon(QString::fromLatin1(entry.icon)));
            actions->addWidget(button);
            m_nativeWatchButtons.push_back(button);
            connect(button, &QPushButton::clicked, this, [this, action = entry.action]
            {
                if (m_nativeWatch && m_nativeWatch->execute)
                {
                    m_nativeWatch->execute(action); // 原页面在此刻冻结事件令牌并再次核对资格。
                }
            });
        }
        m_nativeWatch->changed = [page = QPointer<OfflineSegmentOverview>(this)]
        {
            if (page)
            {
                page->updateNativeWatchToolbar();
            }
        };
        ks::ui::NormalizeToolbarLayout(actions);
        updateNativeWatchToolbar();
    }

    // 输入原页面已发布值，输出按钮资格与明确作用对象；不枚举线程或访问调试器。
    void OfflineSegmentOverview::updateNativeWatchToolbar()
    {
        if (!m_nativeWatch)
        {
            return;
        }
        const auto& state = m_nativeWatch->state; // 与原页面同一回投代次的控制资格。
        for (qsizetype index = 0; index < m_nativeWatchButtons.size(); ++index)
        {
            const auto& entry = kNativeActions[static_cast<std::size_t>(index)];
            auto* button = m_nativeWatchButtons.at(index); // 保留原QPushButton与浮窗宿主关系。
            bool enabled = false;
            switch (entry.action)
            {
            case DataWatchToolbarAction::Pause: enabled = state.canPause; break;
            case DataWatchToolbarAction::Continue: enabled = state.canContinue; break;
            case DataWatchToolbarAction::Into:
            case DataWatchToolbarAction::OverCall:
            case DataWatchToolbarAction::Out: enabled = state.canStep; break;
            case DataWatchToolbarAction::CancelStep: enabled = state.canCancel; break;
            case DataWatchToolbarAction::DumpMemory: enabled = state.canDump; break;
            case DataWatchToolbarAction::Close: enabled = state.canClose; break;
            }
            const auto name = sourceText(entry.text); // 语言切换只更新文本，不更换控制目标。
            auto hint = name + QLatin1Char('\n') + sourceText(QStringLiteral("作用于写入停点页的原生会话，不随总览选区改变。"));
            if (!state.target.isEmpty())
            {
                hint += QLatin1Char('\n') + state.target;
            }
            if (entry.action == DataWatchToolbarAction::DumpMemory)
            {
                hint += QLatin1Char('\n') + sourceText(QStringLiteral("使用写入停点页的内存起点和字节数，读取后保存到本会话项目采样；缺页保留部分结果。"));
            }
            if (!enabled)
            {
                hint += QLatin1Char('\n') + sourceText(QStringLiteral("请先在写入停点页建立会话，并等待对应的真实停止状态。"));
            }
            button->setAccessibleName(name);
            button->setToolTip(hint);
            button->setEnabled(enabled && bool(m_nativeWatch->execute));
        }
    }

    // 连接现有集合会话。操作使用原页面当前精确令牌，历史归档行不具有控制权。
    void OfflineSegmentOverview::setProcessGroupToolbar(std::shared_ptr<ProcessGroupToolbarPort> toolbar)
    {
        if (m_processGroupToolbar || !toolbar)
        {
            return;
        }
        m_processGroupToolbar = std::move(toolbar);
        auto* actions = static_cast<ks::ui::FlowLayout*>(m_actionStrip->layout()); // 与浮出状态共用同一动作带。
        for (const auto& entry : kGroupActions)
        {
            auto* button = new QPushButton(m_actionStrip); // 按钮不持有原生设备或进程句柄。
            button->setObjectName(QString::fromLatin1(entry.name));
            KswordTheme::ApplyStandardIconButtonMetrics(button);
            ks::ui::SetThemeButtonIcon(button, QIcon(QString::fromLatin1(entry.icon)));
            actions->addWidget(button);
            m_processGroupButtons.push_back(button);
            connect(button, &QPushButton::clicked, this, [this, action = entry.action]
            {
                if (m_processGroupToolbar && m_processGroupToolbar->execute)
                {
                    m_processGroupToolbar->execute(action);
                }
            });
        }
        m_processGroupToolbar->changed = [page = QPointer<OfflineSegmentOverview>(this)]
        {
            if (page)
            {
                page->updateProcessGroupToolbar();
            }
        };
        ks::ui::NormalizeToolbarLayout(actions);
        updateProcessGroupToolbar();
    }

    // 按原集合页的已有资格更新各动作，并明确当前全集或选中范围。
    void OfflineSegmentOverview::updateProcessGroupToolbar()
    {
        if (!m_processGroupToolbar)
        {
            return;
        }
        const auto& state = m_processGroupToolbar->state; // 本次集合回投的冻结成员摘要。
        for (qsizetype index = 0; index < m_processGroupButtons.size(); ++index)
        {
            const auto slot = static_cast<std::size_t>(index); // UI目录与固定动作数组保持同序。
            const auto& entry = kGroupActions[slot];
            auto* button = m_processGroupButtons.at(index);
            const auto name = sourceText(entry.text);
            auto hint = name + QLatin1Char('\n') + sourceText(QStringLiteral("作用于进程集合页已核验的实例；选中范围来自该页成员表。"));
            const bool selected = entry.action == ProcessGroupToolbarAction::PauseSelected ||
                entry.action == ProcessGroupToolbarAction::ContinueSelected;
            hint += QLatin1Char('\n') + (selected ? state.selected : state.target);
            if (!state.enabled[slot])
            {
                hint += QLatin1Char('\n') + sourceText(QStringLiteral("请先配置并核验进程集合；继续操作需持有对应成员的完整停止令牌。"));
            }
            button->setAccessibleName(name);
            button->setToolTip(hint);
            button->setEnabled(state.enabled[slot] && bool(m_processGroupToolbar->execute));
        }
    }
}
