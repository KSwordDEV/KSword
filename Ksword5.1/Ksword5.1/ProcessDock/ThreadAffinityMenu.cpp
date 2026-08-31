#include "ThreadAffinityMenu.h"

#include "../Internationalization/LanguageManager.h"
#include "../../../shared/ThreadAffinityR3.h"
#include "../theme.h"

#include <QAction>
#include <QHBoxLayout>
#include <QMenu>
#include <QSignalBlocker>
#include <QStyle>
#include <QToolButton>
#include <QWidget>
#include <QWidgetAction>

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace
{
    QString affinityText(const char* const key, const QString& fallback)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), fallback);
    }

    QString detailTextForResult(const bool success, const std::string& detailText)
    {
        if (success)
        {
            return affinityText(
                "process.thread.affinity.status.updated",
                QStringLiteral("线程亲和性已更新。"));
        }
        const QString detail = QString::fromStdString(detailText);
        return detail.isEmpty()
            ? affinityText(
                "process.thread.affinity.status.failed",
                QStringLiteral("线程亲和性设置失败。"))
            : affinityText(
                "process.thread.affinity.status.failed_with_detail",
                QStringLiteral("线程亲和性设置失败：%1"))
                  .arg(detail);
    }

    QString processorDisplayText(
        const ksword::thread_affinity_r3::LogicalProcessorState& processor,
        const bool includeProcessorGroup)
    {
        QString text = includeProcessorGroup
            ? QStringLiteral("G%1:L%2")
                  .arg(processor.coordinate.group)
                  .arg(processor.coordinate.logicalIndex)
            : QStringLiteral("L%1").arg(processor.coordinate.logicalIndex);
        if (!processor.topologyLabel.empty())
        {
            text += QStringLiteral("\n") + QString::fromStdString(processor.topologyLabel);
        }
        return text;
    }

    bool hasMultipleProcessorGroups(
        const std::vector<ksword::thread_affinity_r3::LogicalProcessorState>& processors)
    {
        std::uint16_t firstGroup = 0U;
        bool hasFirstGroup = false;
        for (const auto& processor : processors)
        {
            if (!hasFirstGroup)
            {
                firstGroup = processor.coordinate.group;
                hasFirstGroup = true;
            }
            else if (processor.coordinate.group != firstGroup)
            {
                return true;
            }
        }
        return false;
    }
}

namespace ks::process
{
    QMenu* addThreadAffinitySubMenu(
        QMenu* const parentMenu,
        const QIcon& icon,
        const DWORD targetProcessId,
        const DWORD targetThreadId,
        const std::uint64_t targetThreadCreationTime100ns,
        const QString& menuStyle,
        ThreadAffinityMenuResultHandler resultHandler)
    {
        if (parentMenu == nullptr)
        {
            return nullptr;
        }

        QMenu* const affinityMenu = parentMenu->addMenu(
            icon,
            affinityText(
                "process.thread.menu.affinity",
                QStringLiteral("线程亲和性")));
        affinityMenu->setStyleSheet(menuStyle);
        affinityMenu->setToolTipsVisible(true);
        affinityMenu->setToolTip(
            affinityText(
                "process.thread.menu.affinity.tooltip",
                QStringLiteral("按逻辑处理器切换此线程的 CPU Set；蓝色按钮表示已启用。")));

        auto snapshot = std::make_shared<ksword::thread_affinity_r3::Snapshot>();
        std::string readDetailText;
        const bool queryOk = ksword::thread_affinity_r3::QueryThreadAffinityState(
            targetThreadId,
            targetProcessId,
            targetThreadCreationTime100ns,
            snapshot.get(),
            &readDetailText);
        if (!queryOk)
        {
            affinityMenu->setEnabled(false);
            affinityMenu->setToolTip(
                affinityText(
                    "process.thread.menu.affinity.unavailable",
                    QStringLiteral("无法读取此线程的 CPU Set 亲和性。")) +
                (readDetailText.empty()
                    ? QString()
                    : QStringLiteral("\n") + QString::fromStdString(readDetailText)));
            return affinityMenu;
        }

        const bool includeProcessorGroup = hasMultipleProcessorGroups(snapshot->processors);
        const QString coreButtonStyle = QStringLiteral(
            "QToolButton {"
            "  min-width:42px; min-height:28px; padding:2px 6px;"
            "  color:%1; background:transparent; border:1px solid %2; border-radius:4px;"
            "}"
            "QToolButton:hover { border-color:%3; background:%4; }"
            "QToolButton:checked { color:%5; background:%3; border-color:%3; }")
                .arg(KswordTheme::TextPrimaryHex())
                .arg(KswordTheme::BorderHex())
                .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))
                .arg(KswordTheme::SurfaceAltHex())
                .arg(KswordTheme::OnAccentDynamicHex());

        QAction* const followProcessAction = affinityMenu->addAction(
            affinityText(
                "process.thread.menu.affinity.follow_process",
                QStringLiteral("跟随进程 CPU Set")));
        followProcessAction->setToolTip(
            affinityText(
                "process.thread.menu.affinity.follow_process.tooltip",
                QStringLiteral("清除线程单独的 CPU Set 选择，继续受所属进程和线程组约束。")));

        const auto coreButtons = std::make_shared<std::vector<QToolButton*>>(
            snapshot->processors.size(),
            nullptr);
        const auto updateCoreButtons = [snapshot, coreButtons]()
        {
            const std::size_t buttonCount = std::min(
                coreButtons->size(),
                snapshot->processors.size());
            for (std::size_t index = 0U; index < buttonCount; ++index)
            {
                QToolButton* const button = (*coreButtons)[index];
                if (button == nullptr)
                {
                    continue;
                }
                const auto& processor = snapshot->processors[index];
                const QSignalBlocker blocker(button);
                button->setEnabled(processor.available);
                button->setChecked(processor.available && processor.selected);
                button->style()->unpolish(button);
                button->style()->polish(button);
                button->update();
            }
        };

        const auto applyRule = [snapshot,
                                    targetProcessId,
                                    targetThreadId,
                                    targetThreadCreationTime100ns,
                                    resultHandler,
                                    updateCoreButtons](
                                   const ksword::thread_affinity_r3::Rule& rule)
        {
            std::string updateDetailText;
            const bool setOk = ksword::thread_affinity_r3::SetThreadAffinityRule(
                targetThreadId,
                targetProcessId,
                targetThreadCreationTime100ns,
                rule,
                &updateDetailText);
            if (setOk)
            {
                ksword::thread_affinity_r3::Snapshot refreshedSnapshot;
                std::string refreshDetailText;
                if (ksword::thread_affinity_r3::QueryThreadAffinityState(
                        targetThreadId,
                        targetProcessId,
                        targetThreadCreationTime100ns,
                        &refreshedSnapshot,
                        &refreshDetailText))
                {
                    *snapshot = std::move(refreshedSnapshot);
                    updateCoreButtons();
                }
                else
                {
                    updateDetailText = refreshDetailText;
                }
            }
            if (resultHandler)
            {
                resultHandler(setOk, detailTextForResult(setOk, updateDetailText));
            }
        };

        QObject::connect(followProcessAction, &QAction::triggered, affinityMenu,
            [applyRule]()
            {
                ksword::thread_affinity_r3::Rule rule;
                rule.followProcessCpuSets = true;
                applyRule(rule);
            });

        constexpr std::size_t kAffinityMatrixColumnCount = 6U;
        for (std::size_t rowStart = 0U;
             rowStart < snapshot->processors.size();
             rowStart += kAffinityMatrixColumnCount)
        {
            QWidgetAction* const rowAction = new QWidgetAction(affinityMenu);
            QWidget* const rowWidget = new QWidget(affinityMenu);
            QHBoxLayout* const rowLayout = new QHBoxLayout(rowWidget);
            rowLayout->setContentsMargins(8, 3, 8, 3);
            rowLayout->setSpacing(6);
            const std::size_t rowEnd = std::min(
                rowStart + kAffinityMatrixColumnCount,
                snapshot->processors.size());
            for (std::size_t index = rowStart; index < rowEnd; ++index)
            {
                const auto coordinate = snapshot->processors[index].coordinate;
                QToolButton* const coreButton = new QToolButton(rowWidget);
                coreButton->setText(processorDisplayText(snapshot->processors[index], includeProcessorGroup));
                coreButton->setCheckable(true);
                coreButton->setAutoRaise(false);
                coreButton->setFocusPolicy(Qt::NoFocus);
                coreButton->setStyleSheet(coreButtonStyle);
                coreButton->setToolTip(
                    affinityText(
                        "process.thread.menu.affinity.core_tooltip",
                        QStringLiteral("%1；点击切换此线程的 CPU Set。"))
                        .arg(processorDisplayText(snapshot->processors[index], includeProcessorGroup)) +
                    (snapshot->processors[index].constrainedByThreadOrProcessAffinity
                        ? QStringLiteral("\n") + affinityText(
                            "process.thread.menu.affinity.constraint_tooltip",
                            QStringLiteral("受线程组或所属进程的 CPU Set 规则约束，当前不可调度到此处理器。"))
                        : QString()));
                rowLayout->addWidget(coreButton);
                (*coreButtons)[index] = coreButton;
                QObject::connect(coreButton, &QToolButton::clicked, affinityMenu,
                    [snapshot, coordinate, coreButton, applyRule, updateCoreButtons](const bool enabled)
                    {
                        ksword::thread_affinity_r3::Rule nextRule;
                        if (snapshot->followsProcessCpuSets)
                        {
                            for (const auto& processor : snapshot->processors)
                            {
                                if (processor.available)
                                {
                                    nextRule.processors.push_back(processor.coordinate);
                                }
                            }
                        }
                        else
                        {
                            for (const auto& processor : snapshot->processors)
                            {
                                if (processor.available && processor.selected)
                                {
                                    nextRule.processors.push_back(processor.coordinate);
                                }
                            }
                        }
                        auto coordinateIt = std::find(
                            nextRule.processors.begin(),
                            nextRule.processors.end(),
                            coordinate);
                        if (enabled && coordinateIt == nextRule.processors.end())
                        {
                            nextRule.processors.push_back(coordinate);
                        }
                        else if (!enabled && coordinateIt != nextRule.processors.end())
                        {
                            nextRule.processors.erase(coordinateIt);
                        }
                        ksword::thread_affinity_r3::normalizeCoordinates(&nextRule.processors);
                        if (nextRule.processors.empty())
                        {
                            const QSignalBlocker blocker(coreButton);
                            coreButton->setChecked(true);
                            updateCoreButtons();
                            return;
                        }
                        applyRule(nextRule);
                    });
            }
            rowLayout->addStretch(1);
            rowAction->setDefaultWidget(rowWidget);
            affinityMenu->addAction(rowAction);
        }

        followProcessAction->setEnabled(std::any_of(
            snapshot->processors.begin(),
            snapshot->processors.end(),
            [](const ksword::thread_affinity_r3::LogicalProcessorState& processor)
            {
                return processor.available;
            }));
        updateCoreButtons();
        return affinityMenu;
    }
}
