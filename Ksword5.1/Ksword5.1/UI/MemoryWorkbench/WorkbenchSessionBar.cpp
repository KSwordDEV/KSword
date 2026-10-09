#include "WorkbenchSessionBar.h"

// ============================================================
// WorkbenchSessionBar.cpp
// 作用：见头文件。关键约束再强调一遍——setScope/setChannel/setSession 都只是
// "回写显示"，本文件里唯一会修改 ChannelMemory（通道记忆）的地方是 setChannel
// 与 setSession（仅 rememberAsUserChoice 为真时）；setScope 只读取 Recall，不
// 写入，因为"范围切换本身不代表用户选了新通道"。
//
// S5 补充说明（setSession 存在的理由）：原来的用法是调用方分两步
// setChannel(新通道)→setScope(新范围)，而 setChannel 内部按"当前 m_scope"记忆——
// 如果调用方先调 setChannel 再调 setScope（两步谁先谁后完全取决于装配层的写法），
// 新通道就会被错记进"旧范围"的记忆里。setSession 把两步的顺序锁死在函数内部
// （先定范围、再按需记忆、最后刷新显示），调用方不必再操心调用顺序。
//
// S4 补充说明（handleScopeSegmentChanged/handleChannelSegmentChanged 为什么要排一次
// 延迟回写）：HexViewSegmented 点击后会自己先把当前项切过去、再发
// scopeRequested/channelRequested；如果装配层否决了这次请求（例如暂存区离开
// 守卫拒绝）却忘了显式调 setScope/setChannel 把显示拨回去，界面就会停在"看起来
// 已经切换，但会话实际没动"的状态——这正是旧缺陷"R0 读取实际走的是 R3"的同一
// 形状。本文件在请求发出后的下一个事件循环里，主动把分段显示重新同步回
// m_scope/m_channel：装配层接受了请求、已经调用过 setScope/setChannel 的话，这里
// 读到的就是新值，等于空操作；装配层忘了处理或者拒绝了请求，这里就会把显示
// 兜底拨回真正生效的那个值。
// ============================================================

#include "WorkbenchMessages.h"
#include "WriteModeSwitch.h"
#include "../../Internationalization/LanguageManager.h"

#include "../FlowLayout.h"
#include "HexViewWidgets.h"

#include "../../theme.h"

#include <QColor>
#include <QEvent>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QPalette>
#include <QSignalBlocker>
#include <QTimer>
#include <QToolButton>

namespace ks::ui
{
    using ksword::memwb::Channel;
    using ksword::memwb::ChannelSupportsScope;
    using ksword::memwb::GateReason;
    using ksword::memwb::GateVerdict;
    using ksword::memwb::Scope;
    using ksword::memwb::WriteMode;

    namespace
    {
        // kChannelCount：通道总数，与 Channel 枚举的四个取值一致。
        constexpr int kChannelCount = 4;

        // ScopeNeedsProcess：B3——只有进程范围才需要一个目标进程；内核/物理范围
        // 根本不存在"选目标"这一步，目标 chip 不该显示红字"未附加"，也不该在
        // 点击后发出 pickTargetRequested 去选一个用不上的进程。
        bool ScopeNeedsProcess(const Scope scope)
        {
            return scope == Scope::ProcessVirtual;
        }

        // ScopeLabels / ChannelLabels：两个分段按钮的段文字，顺序对应各自枚举的数值。
        QStringList ScopeLabels()
        {
            return {
                workbench_messages::ScopeName(Scope::ProcessVirtual),
                workbench_messages::ScopeName(Scope::KernelVirtual),
                workbench_messages::ScopeName(Scope::Physical),
            };
        }

        QStringList ChannelLabels()
        {
            return {
                workbench_messages::ChannelName(Channel::UserMode),
                workbench_messages::ChannelName(Channel::StandardDriver),
                workbench_messages::ChannelName(Channel::Hvm),
                workbench_messages::ChannelName(Channel::Ddma),
            };
        }
    }

    WorkbenchSessionBar::WorkbenchSessionBar(QWidget* parent)
        : QWidget(parent)
    {
        // FlowLayout：窄窗口自动换行，容纳范围/通道/目标/模式/待写入五组控件。
        m_flow = new FlowLayout(this, 4, 6, 4);

        m_scopeSegmented = new HexViewSegmented(ScopeLabels(), this);
        m_scopeSegmented->setSegmentToolTip(
            static_cast<int>(Scope::ProcessVirtual), workbench_messages::ScopeName(Scope::ProcessVirtual));
        m_scopeSegmented->setSegmentToolTip(
            static_cast<int>(Scope::KernelVirtual), workbench_messages::ScopeName(Scope::KernelVirtual));
        m_scopeSegmented->setSegmentToolTip(
            static_cast<int>(Scope::Physical), workbench_messages::ScopeName(Scope::Physical));
        connect(m_scopeSegmented, &HexViewSegmented::currentIndexChanged,
            this, &WorkbenchSessionBar::handleScopeSegmentChanged);
        m_flow->addWidget(m_scopeSegmented);

        m_channelSegmented = new HexViewSegmented(ChannelLabels(), this);
        for (int i = 0; i < kChannelCount; ++i)
        {
            m_channelSegmented->setSegmentToolTip(i, workbench_messages::ChannelDescription(static_cast<Channel>(i)));
        }
        connect(m_channelSegmented, &HexViewSegmented::currentIndexChanged,
            this, &WorkbenchSessionBar::handleChannelSegmentChanged);
        m_flow->addWidget(m_channelSegmented);

        // channelWarning：平时隐藏，只在当前选中通道不可用/未知时显示原因。
        m_channelWarning = new HexViewMessageLabel(this);
        m_channelWarning->setVisible(false);
        m_flow->addWidget(m_channelWarning);

        // 目标 chip：只读展示，点击总是请求外部处理（选择/附加/钉住具体做什么由装配层决定）。
        m_targetChip = new QToolButton(this);
        m_targetChip->setAutoRaise(true);
        m_targetChip->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
        m_targetChip->setIcon(QIcon(QStringLiteral(":/Icon/process_main.svg")));
        m_targetChip->setIconSize(KswordTheme::CompactIconSize());
        m_targetChip->setFocusPolicy(Qt::TabFocus);
        // B3：当前范围不需要进程（内核/物理）时，点击不发 pickTargetRequested——
        // 发了也没有意义，装配层会被迫处理一个"选进程"请求，而当前范围根本用不上。
        connect(m_targetChip, &QToolButton::clicked, this, [this]() {
            if (ScopeNeedsProcess(m_scope))
            {
                emit pickTargetRequested();
            }
        });
        m_flow->addWidget(m_targetChip);

        m_writeModeSwitch = new WriteModeSwitch(this);
        connect(m_writeModeSwitch, &WriteModeSwitch::modeToggleRequested,
            this, &WorkbenchSessionBar::handleModeToggleRequested);
        m_flow->addWidget(m_writeModeSwitch);

        // 待写入区：三个子控件装进一个容器，整条一起显隐。
        m_pendingContainer = new QWidget(this);
        auto* pendingLayout = new QHBoxLayout(m_pendingContainer);
        pendingLayout->setContentsMargins(0, 0, 0, 0);
        pendingLayout->setSpacing(4);
        m_pendingLabel = new QLabel(m_pendingContainer);
        m_pendingLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        pendingLayout->addWidget(m_pendingLabel);
        m_applyButton = new QToolButton(m_pendingContainer);
        m_applyButton->setIcon(QIcon(QStringLiteral(":/Icon/service_apply.svg")));
        m_applyButton->setToolTip(workbench_messages::ApplyButtonTooltip());
        KswordTheme::ApplyCompactIconButtonMetrics(m_applyButton);
        connect(m_applyButton, &QToolButton::clicked, this, &WorkbenchSessionBar::applyRequested);
        pendingLayout->addWidget(m_applyButton);
        m_discardButton = new QToolButton(m_pendingContainer);
        m_discardButton->setIcon(QIcon(QStringLiteral(":/Icon/log_clear.svg")));
        m_discardButton->setToolTip(workbench_messages::DiscardButtonTooltip());
        KswordTheme::ApplyCompactIconButtonMetrics(m_discardButton);
        connect(m_discardButton, &QToolButton::clicked, this, &WorkbenchSessionBar::discardRequested);
        pendingLayout->addWidget(m_discardButton);
        m_pendingContainer->setVisible(false);
        m_flow->addWidget(m_pendingContainer);

        // 初始状态：范围=进程，通道按 ChannelMemory 的默认值回显，目标未附加。
        applyChannelDisplay(m_channelMemory.Recall(m_scope));
        setTargetInfo(false, QString(), 0, 64, false);
    }

    Scope WorkbenchSessionBar::currentScope() const { return m_scope; }
    Channel WorkbenchSessionBar::currentChannel() const { return m_channel; }
    WriteMode WorkbenchSessionBar::currentWriteMode() const { return m_writeMode; }
    WriteModeSwitch* WorkbenchSessionBar::writeModeSwitch() const { return m_writeModeSwitch; }
    HexViewSegmented* WorkbenchSessionBar::scopeSegmented() const { return m_scopeSegmented; }
    HexViewSegmented* WorkbenchSessionBar::channelSegmented() const { return m_channelSegmented; }

    void WorkbenchSessionBar::setScope(const Scope scope)
    {
        m_scope = scope;
        {
            // 用 QSignalBlocker 避免这次"回写"被当成用户又点了一次而重新发请求信号。
            const QSignalBlocker blocker(m_scopeSegmented);
            m_scopeSegmented->setCurrentIndex(static_cast<int>(scope));
        }
        // 核心规则：通道取该范围"上次使用"，不是自动选个默认值，也不看此刻是否可用。
        applyChannelDisplay(m_channelMemory.Recall(scope));
        // B3：范围变了，目标 chip 要不要显示"无需进程"也跟着变。
        refreshTargetChipDisplay();
    }

    void WorkbenchSessionBar::setSession(
        const Scope scope, const Channel channel, const bool rememberAsUserChoice)
    {
        // S5：先把 m_scope 定下来，再决定要不要记忆——这样 Remember(m_scope, channel)
        // 读到的恒是"新范围"，不会像"分两步调用 setChannel 再 setScope"那样，
        // 因为调用顺序不同而把新通道记进了旧范围。
        m_scope = scope;
        {
            const QSignalBlocker blocker(m_scopeSegmented);
            m_scopeSegmented->setCurrentIndex(static_cast<int>(scope));
        }
        if (rememberAsUserChoice)
        {
            // 用户的显式选择才值得记住；程序化强制切换的通道（例如"R0 读取此区域"）
            // 不经这条路径写记忆，不会覆盖用户本来的偏好。
            m_channelMemory.Remember(m_scope, channel);
        }
        applyChannelDisplay(channel);
        refreshTargetChipDisplay();
    }

    void WorkbenchSessionBar::setChannelVerdicts(const std::array<GateVerdict, 4>& verdicts)
    {
        // N6：从这里起 m_lastVerdicts 才是"装配层真的判定过"的结果，
        // refreshChannelSegmentStates 据 m_hasVerdicts 决定要不要采信它。
        m_hasVerdicts = true;
        m_lastVerdicts = verdicts;
        refreshChannelSegmentStates();
    }

    void WorkbenchSessionBar::setChannel(const Channel channel)
    {
        // 只有这里（与 setSession 的 rememberAsUserChoice 分支）会写 ChannelMemory：
        // 用户（或装配层代表用户）显式选中的通道才值得记住。
        m_channelMemory.Remember(m_scope, channel);
        applyChannelDisplay(channel);
    }

    Channel WorkbenchSessionBar::rememberedChannel(const Scope scope) const
    {
        return m_channelMemory.Recall(scope);
    }

    void WorkbenchSessionBar::restoreChannelMemory(const Scope scope, const std::uint32_t channelValue)
    {
        m_channelMemory.Restore(scope, channelValue);
    }

    void WorkbenchSessionBar::applyChannelDisplay(const Channel channel)
    {
        m_channel = channel;
        {
            const QSignalBlocker blocker(m_channelSegmented);
            m_channelSegmented->setCurrentIndex(static_cast<int>(channel));
        }
        refreshChannelSegmentStates();
    }

    void WorkbenchSessionBar::refreshChannelSegmentStates()
    {
        // B14：m_lastVerdicts 是调用方按"上一个范围"喂的判据——setScope 切到新范围
        // 之后，调用方很可能还没来得及重新喂一遍。这里用静态的 ChannelSupportsScope
        // 表强行兜底：范围根本不支持的通道，不管旧判据怎么说都必须显示成不可用，
        // 否则会出现"不支持的通道可点"的瞬态缺陷。注意：这里只在**本地变量**里做
        // 兜底，绝不回写 m_lastVerdicts——调用方喂的原始判据必须原样保留，范围切
        // 回去之后才能用回真实判据，而不是之前兜底出来的"假不可用"。
        for (int i = 0; i < kChannelCount; ++i)
        {
            const Channel channel = static_cast<Channel>(i);
            // N6：还没收到过第一次判据时，GateVerdict{} 的默认值
            // {false, InvalidRequest} 不能当真——那只是结构体的"零值"，不是"已经
            // 判定过不行"。此时先假定每个通道都可用（{true, None}），下面仍会用
            // 静态的 ChannelSupportsScope 表纠正结构性不支持的组合，不会让真正
            // 不支持的通道（例如内核范围下的 R3）在"还不知道"期间也显示可点。
            GateVerdict effective = m_hasVerdicts
                ? m_lastVerdicts[static_cast<std::size_t>(i)]
                : GateVerdict{ true, GateReason::None };
            if (!ChannelSupportsScope(channel, m_scope))
            {
                effective = GateVerdict{ false, GateReason::ScopeNotSupported };
            }
            // available 为真就让分段保持可点（含 IsUnknown：未知允许选用，不得置灰）；
            // 置灰时的提示文字固定是"不可用原因"。
            m_channelSegmented->setSegmentEnabled(
                i, effective.available, workbench_messages::ChannelUnavailableReason(channel, effective));
        }

        const auto channelIndex = static_cast<std::size_t>(m_channel);
        // N6：同上，没有真实判据之前，当前选中通道也先假定可用、不报任何原因。
        GateVerdict current = (m_hasVerdicts && channelIndex < m_lastVerdicts.size())
            ? m_lastVerdicts[channelIndex]
            : GateVerdict{ true, GateReason::None };
        if (!ChannelSupportsScope(m_channel, m_scope))
        {
            current = GateVerdict{ false, GateReason::ScopeNotSupported };
        }
        if (!current.available)
        {
            // 当前选中的通道此刻被判定不可用：保持选中（不替用户换），只报红说明原因。
            m_channelWarning->setMessage(
                HexViewMessageLabel::Kind::Error,
                workbench_messages::ChannelUnavailableReason(m_channel, current));
        }
        else if (current.IsUnknown())
        {
            // 可用性尚未探测完成：允许继续选用，用警告色而不是错误色提示"还不确定"。
            m_channelWarning->setMessage(
                HexViewMessageLabel::Kind::Warning,
                workbench_messages::ChannelUnavailableReason(m_channel, current));
        }
        else
        {
            m_channelWarning->clearMessage();
        }
        m_channelWarning->setVisible(!current.available || current.IsUnknown());
    }

    QString WorkbenchSessionBar::channelWarningText() const
    {
        // B8：isVisible() 要求整条祖先链都真的 show() 过，会话条所在页签被切走
        // （父级隐藏）时会读成空——但提示本身并没有被清空，只是暂时不在屏幕上。
        // isHidden() 只问"本控件自己有没有被 setVisible(false)"，不看祖先链。
        return !m_channelWarning->isHidden() ? m_channelWarning->text() : QString();
    }

    void WorkbenchSessionBar::setWriteMode(const WriteMode mode)
    {
        m_writeMode = mode;
        m_writeModeSwitch->setMode(mode);
    }

    void WorkbenchSessionBar::handleScopeSegmentChanged(const int index)
    {
        emit scopeRequested(static_cast<Scope>(index));
        // S4：下一个事件循环里把分段显示重新同步回 m_scope——装配层已经调用过
        // setScope 的话这里是空操作；没调用（忘了处理或拒绝了请求）的话，这里把
        // 显示兜底拨回真正生效的范围，不会停在"看起来已切换、会话其实没动"。
        QTimer::singleShot(0, this, [this]() {
            const QSignalBlocker blocker(m_scopeSegmented);
            m_scopeSegmented->setCurrentIndex(static_cast<int>(m_scope));
        });
    }

    void WorkbenchSessionBar::handleChannelSegmentChanged(const int index)
    {
        emit channelRequested(static_cast<Channel>(index));
        // S4：理由同上，针对通道分段。
        QTimer::singleShot(0, this, [this]() {
            const QSignalBlocker blocker(m_channelSegmented);
            m_channelSegmented->setCurrentIndex(static_cast<int>(m_channel));
        });
    }

    void WorkbenchSessionBar::handleModeToggleRequested(const WriteMode requestedMode)
    {
        emit modeRequested(requestedMode);
    }

    void WorkbenchSessionBar::setMemoryDebugMode(const bool enabled)
    {
        m_memoryDebugMode = enabled;
        // 独立页恒为进程地址空间；保留通道、写入模式和目标选择按钮。
        m_scopeSegmented->setVisible(!enabled);
        refreshTargetChipDisplay();
    }

    void WorkbenchSessionBar::setTargetInfo(
        const bool attached,
        const QString& processName,
        const quint32 pid,
        const quint32 addressBits,
        const bool canReadWrite)
    {
        // 把四个参数存成员，供 refreshTargetChipDisplay 在范围/主题变化时重新拼
        // 文字，不强求调用方每次范围变化都重新调一遍 setTargetInfo。
        m_attached = attached;
        m_targetProcessName = processName;
        m_targetPid = pid;
        m_targetAddressBits = addressBits;
        m_targetCanReadWrite = canReadWrite;
        refreshTargetChipDisplay();
    }

    void WorkbenchSessionBar::refreshTargetChipDisplay()
    {
        // B3：内核/物理范围不需要进程，chip 显示中性提示，不是"未附加"的红字；
        // 进程范围则沿用原来的"已附加/未附加"两态逻辑。三种状态三种颜色：
        // 中性（次级文字色）、正常（主文字色）、警告（错误色）。
        QString text;
        QColor textColor;
        if (!ScopeNeedsProcess(m_scope))
        {
            text = workbench_messages::TargetChipNoProcessText(m_scope);
            textColor = KswordTheme::TextSecondaryColor();
        }
        else if (m_attached)
        {
            text = workbench_messages::TargetChipAttachedText(
                m_targetProcessName, m_targetPid, m_targetAddressBits, m_targetCanReadWrite);
            textColor = KswordTheme::TextPrimaryColor();
        }
        else
        {
            text = m_memoryDebugMode
                ? ks::i18n::sourceText(QStringLiteral("未选择进程"))
                : workbench_messages::TargetChipUnattachedText();
            textColor = KswordTheme::ErrorColor();
        }
        m_targetChip->setText(text);
        // S-e：内核/物理范围不需要进程，tooltip 不该还暗示"点它能选进程"；按
        // ScopeNeedsProcess 传给 TargetChipTooltip 决定文案分支。
        m_targetChip->setToolTip(m_memoryDebugMode
            ? ks::i18n::sourceText(QStringLiteral("选择进程"))
            : workbench_messages::TargetChipTooltip(ScopeNeedsProcess(m_scope)));
        QPalette palette = m_targetChip->palette();
        palette.setColor(QPalette::ButtonText, textColor);
        m_targetChip->setPalette(palette);
    }

    void WorkbenchSessionBar::setPendingPatches(const quint64 bytesPending, const quint64 blocksPending)
    {
        refreshPendingVisibility();
        m_pendingContainer->setVisible(bytesPending > 0);
        if (bytesPending > 0)
        {
            m_pendingLabel->setText(workbench_messages::PendingPatchesText(bytesPending, blocksPending));
        }
    }

    void WorkbenchSessionBar::refreshPendingVisibility()
    {
        // 预留给未来扩展（例如暂存区本身被禁用时强制隐藏）；目前只是个占位的转发点，
        // 真正的显隐判断就是 bytesPending>0，写在 setPendingPatches 里。
    }

    void WorkbenchSessionBar::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event);
        // N7：QEvent::ApplicationPaletteChange 是发给 QApplication 自己的事件，
        // QWidget::event 不会把它转发成子控件的 changeEvent（这条分支过去一直是
        // 死代码，实测主题切换后 chip 的文字色不会跟着更新）。一个控件自己的有效
        // 调色板真正变化时收到的是 QEvent::PaletteChange；连带监听 StyleChange，
        // 与仓库里其它监听主题变化的控件（见 KernelDock/MonitorDock 等文件同类
        // changeEvent 写法）保持一致。
        if (event != nullptr
            && (event->type() == QEvent::PaletteChange
                || event->type() == QEvent::ApplicationPaletteChange
                || event->type() == QEvent::StyleChange))
        {
            refreshTargetChipDisplay();
        }
    }
}
