#pragma once

// ============================================================
// WorkbenchSessionBar.h
// 作用：
// - 工作台的会话条（ux.md 第 2 节）：范围分段（进程|内核|物理）、通道分段
//   （R3|R0|HVM|DDMA）、只读目标 chip、写入模式开关、待写入区。
// - 本控件只发"请求"信号（scopeRequested/channelRequested/modeRequested/
//   applyRequested/discardRequested/pickTargetRequested），自己不改任何业务
//   状态；调用方（装配层）审核请求之后，通过 setScope/setChannel/setWriteMode/
//   setTargetInfo/setPendingPatches 把最终生效的状态回写，本控件只负责显示。
// - “绝不自动换通道”：切换范围时，通道分段显示的是该范围在 ChannelMemory 里
//   记住的"上次使用"，不是自动回退到某个默认值；通道此刻不可用时分段保持选中
//   且用一条报红提示说明原因，不会替用户换成别的通道。ChannelMemory 的语义
//   冻结在 shared/evidence/memory_workbench/MemoryChannelGate.h，本控件只是
//   它的一个使用者，不重新实现判定逻辑。
// ============================================================

#include <QString>
#include <QWidget>

#include "../../../../shared/evidence/memory_workbench/MemoryChannelGate.h"
#include "../../../../shared/evidence/memory_workbench/MemoryTargetSession.h"
#include "../../../../shared/evidence/memory_workbench/MemoryWriteTransaction.h"

#include <array>
#include <cstdint>

class QLabel;
class QToolButton;
class QWidget;

namespace ks::ui
{
    class FlowLayout;
    class HexViewSegmented;
    class HexViewMessageLabel;
    class WriteModeSwitch;

    // WorkbenchSessionBar：会话条控件。
    class WorkbenchSessionBar final : public QWidget
    {
        Q_OBJECT

    public:
        explicit WorkbenchSessionBar(QWidget* parent = nullptr);

        // setMemoryDebugMode：独立页隐藏范围切换，并把目标提示改为进程选择。
        // 传入 enabled：是否使用该显示模式；不改变目标或通道，不发业务请求。
        void setMemoryDebugMode(bool enabled);

        // currentScope / currentChannel / currentWriteMode：当前显示的状态
        //（由 set* 系列回写，不代表用户刚点的那一次请求一定已经生效）。
        ksword::memwb::Scope currentScope() const;
        ksword::memwb::Channel currentChannel() const;
        ksword::memwb::WriteMode currentWriteMode() const;

        // setScope：调用方确认范围切换后调用。内部按 ChannelMemory::Recall 回显该
        // 范围"上次使用"的通道（不发 channelRequested，纯粹是显示回写），随后
        // 沿用最近一次 setChannelVerdicts 给的判据重新计算是否报红。
        void setScope(ksword::memwb::Scope scope);

        // setChannelVerdicts：四个通道在"当前范围、此刻运行期条件"下的可用性判据，
        // 下标即 Channel 的数值（0=R3，1=R0，2=HVM，3=DDMA）。调用方用 Core 的
        // EvaluateChannel 算好后传入；本控件据此刷新四个分段的置灰/提示，并在
        // 当前选中通道不可用时显示报红提示（不改选中）。
        void setChannelVerdicts(const std::array<ksword::memwb::GateVerdict, 4>& verdicts);

        // setChannel：调用方确认通道切换后调用。写入 ChannelMemory 作为该范围的
        // "上次使用"，并刷新分段选中与报红状态。
        void setChannel(ksword::memwb::Channel channel);

        // setWriteMode：调用方确认模式切换后调用，纯回显，不发 modeRequested。
        void setWriteMode(ksword::memwb::WriteMode mode);

        // setTargetInfo：刷新只读目标 chip。attached 为假时忽略其余参数，显示
        // "未附加进程"的红字提示；为真时按参数拼"名 · PID · 位数 · 可读写"。
        // B3：当前范围是内核/物理（ScopeNeedsProcess 为假）时，本函数的结果会被
        // "无需进程"的中性提示覆盖——那两个范围压根不存在"选目标"这一步，不该
        // 让用户看见"未附加进程"的红字警告。
        void setTargetInfo(
            bool attached,
            const QString& processName,
            quint32 pid,
            quint32 addressBits,
            bool canReadWrite);

        // setSession：装配层在一次操作里同时确认范围与通道时的组合入口（S5）。
        // rememberAsUserChoice 为真才会把 channel 记进 ChannelMemory（供下次切回
        // 该范围时回显）；为假只刷新显示，不碰记忆——用于"R0 读取此区域"这类程序
        // 化强制切换的通道，不该被当成用户的长期偏好记住。比起分别调用
        // setScope+setChannel，本函数避免了 setChannel 读取 m_scope 时读到"旧范围"
        // 这个与调用顺序相关的陷阱（见 WorkbenchSessionBar.cpp 顶部 S5 说明）。
        void setSession(
            ksword::memwb::Scope scope,
            ksword::memwb::Channel channel,
            bool rememberAsUserChoice);

        // rememberedChannel：读出某个范围在 ChannelMemory 里记住的"上次使用"通道
        //（B5）。供装配层启动时把三个范围的记忆整体持久化到 WorkbenchSettings 的
        // channel/process|kernel|physical 三个键；直接转发 Core 的 Recall，不清洗。
        ksword::memwb::Channel rememberedChannel(ksword::memwb::Scope scope) const;

        // restoreChannelMemory：装配层启动时，把某个范围从持久化读回的通道值灌回
        // ChannelMemory（B5）。只灌记忆本身，不刷新显示、不发任何信号——调用方应
        // 在三个范围都灌完之后，再调用一次 setScope(初始范围) 把界面真正显示出来。
        // 转发 Core 的 Restore（会清洗 DDMA/越界值："DDMA 永不作启动默认"由 Core
        // 的 Restore 保证，本函数不重复实现这条清洗规则）。
        void restoreChannelMemory(ksword::memwb::Scope scope, std::uint32_t channelValue);

        // setPendingPatches：刷新"N 字节待写入"区域；bytesPending 为 0 时整条隐藏
        //（HasPendingPatches() 为假时的唯一合法状态）。
        void setPendingPatches(quint64 bytesPending, quint64 blocksPending);

        // channelWarningText：当前选中通道此刻报红时显示的原因文本，空串表示未报红；
        // 主要供夹具/测试直接读取断言，生产界面也可用它做状态条的补充说明。
        QString channelWarningText() const;

        // writeModeSwitch / sessionBarSegments：供测试与诸如 WorkbenchActions 的
        // 快捷键挂载点直接拿到内部控件指针，不强行重新包一层委托方法。
        WriteModeSwitch* writeModeSwitch() const;
        HexViewSegmented* scopeSegmented() const;
        HexViewSegmented* channelSegmented() const;

    signals:
        // scopeRequested / channelRequested：用户点了某个分段；参数是被点中的值，
        // 不代表已经生效。
        void scopeRequested(ksword::memwb::Scope scope);
        void channelRequested(ksword::memwb::Channel channel);
        // modeRequested：用户点了写入模式胶囊的另一半，或按了空格。
        void modeRequested(ksword::memwb::WriteMode mode);
        // applyRequested / discardRequested：用户点了待写入区的 ✓/✗。
        void applyRequested();
        void discardRequested();
        // pickTargetRequested：用户点了"未附加"状态的目标 chip。
        void pickTargetRequested();

    protected:
        // changeEvent：主题变化时刷新目标 chip 的报红/报灰静态颜色样式。
        void changeEvent(QEvent* event) override;

    private slots:
        // handleScopeSegmentChanged：范围分段被（用户或代码）切换时触发。
        void handleScopeSegmentChanged(int index);
        // handleChannelSegmentChanged：通道分段被（用户或代码）切换时触发。
        void handleChannelSegmentChanged(int index);
        // handleModeToggleRequested：写入模式胶囊请求切换时触发，原样转发为 modeRequested。
        void handleModeToggleRequested(ksword::memwb::WriteMode requestedMode);

    private:
        // applyChannelDisplay：把通道分段的选中项与四段的置灰/提示刷新到 channel；
        // 不发任何信号，供 setScope/setChannel/setChannelVerdicts 共用。
        void applyChannelDisplay(ksword::memwb::Channel channel);

        // refreshChannelSegmentStates：按 m_lastVerdicts 重新计算四段的置灰/提示，
        // 并刷新"当前通道报红"提示的文字与可见性。
        void refreshChannelSegmentStates();

        // refreshTargetChipDisplay：按 m_scope/m_attached/已存的目标信息重新计算目标
        // chip 的文字与颜色（B3：内核/物理范围显示"无需进程"的中性提示，不是红字
        // "未附加"）。setScope/setTargetInfo/changeEvent 都要调它——范围变化、附加
        // 信息变化、主题变化，三类事件都可能需要重新算这一个 chip 的最终展示。
        void refreshTargetChipDisplay();

        // refreshPendingVisibility：按 m_pendingBytes 是否为 0 显隐待写入区域。
        void refreshPendingVisibility();

        // m_channelMemory：每个范围"上次使用的通道"的显式记忆（Core 类型）。
        ksword::memwb::ChannelMemory m_channelMemory;
        // m_scope / m_channel / m_writeMode：当前显示的三个状态字段。
        ksword::memwb::Scope m_scope = ksword::memwb::Scope::ProcessVirtual;
        ksword::memwb::Channel m_channel = ksword::memwb::Channel::UserMode;
        ksword::memwb::WriteMode m_writeMode = ksword::memwb::WriteMode::Immediate;
        // m_lastVerdicts：最近一次 setChannelVerdicts 给的四段判据，供 setScope 之后
        // 立刻重新计算报红状态（范围变了但调用方可能还没来得及重新喂判据）。
        std::array<ksword::memwb::GateVerdict, 4> m_lastVerdicts{};
        // m_hasVerdicts：是否已经收到过至少一次 setChannelVerdicts（N6，第二轮修复）。
        // 构造后、装配层第一次探测完成前，m_lastVerdicts 四项都是 GateVerdict 的
        // 默认值 {false, InvalidRequest}——那只是"结构体尚未被赋过值"的巧合，不是
        // "已经判定过、结论是当前范围/通道组合无效"。refreshChannelSegmentStates 据
        // 这个旗标区分"还不知道"（不置灰、不报任何原因）与"已经知道不行"两种
        // 完全不同的情况，为真之后才会真正采信 m_lastVerdicts 里的内容。
        bool m_hasVerdicts = false;
        // m_attached：目标 chip 当前是否处于"已附加"状态，供 refreshTargetChipDisplay
        // 在范围/主题变化时重新计算展示（不必重新调用一次 setTargetInfo）。
        bool m_attached = false;
        // m_memoryDebugMode：仅控制独立内存调试页的范围控件与目标文案。
        bool m_memoryDebugMode = false;
        // m_targetProcessName/m_targetPid/m_targetAddressBits/m_targetCanReadWrite：
        // setTargetInfo 最近一次喂入的四个参数，供 refreshTargetChipDisplay 在范围/
        // 主题变化时重新拼文字，不必要求调用方重新调一次 setTargetInfo。
        QString m_targetProcessName;
        quint32 m_targetPid = 0;
        quint32 m_targetAddressBits = 64;
        bool m_targetCanReadWrite = false;

        FlowLayout* m_flow = nullptr;
        HexViewSegmented* m_scopeSegmented = nullptr;
        HexViewSegmented* m_channelSegmented = nullptr;
        HexViewMessageLabel* m_channelWarning = nullptr;
        QToolButton* m_targetChip = nullptr;
        WriteModeSwitch* m_writeModeSwitch = nullptr;
        QWidget* m_pendingContainer = nullptr;
        QLabel* m_pendingLabel = nullptr;
        QToolButton* m_applyButton = nullptr;
        QToolButton* m_discardButton = nullptr;
    };
}
