// 内存工作台目标跟踪器（shared/evidence/memory_workbench/MemoryTargetTracker.h）的离线测试。
//
// 为什么这个模块值得一整套穷举断言：它属于**判错了不会报错**的那一类。
// 跟踪器漏掉一次"该 bump"，界面照样显示、驱动照样去读，只是读的是上一个目标；
// 多 bump 一次则让已读的页被无谓丢弃。具体到本模块有四处：
//   * 内核/物理范围下仍被 Dock 的附加/分离牵动 -> 每次重附加都丢页；
//   * 离开 Ddma 通道后旧的暂存扇区代次残留 -> 回到 Ddma 时误当成新鲜；
//   * 钉住代次与 Dock 代次相撞 -> 钉住的目标被当成 Dock 重附加的同一个目标；
//   * 同身份的钉住也 bump -> 已读页无故作废。
//
// 断言原则与 MemoryTargetSessionTests.cpp 一致：
//   * 期望值手算写死（含钉住代次的具体数值），不从被测函数反算；
//   * 边界两侧都测（Dock 代次 2^63 的两侧、位宽 32/64 与邻近非法值）；
//   * 拒绝路径显式测，并且断言"拒绝后状态完全没变、也没有悄悄记账"；
//   * 1 万步确定性伪随机游走（两条核心性质 + 独立参考模型对拍 + 覆盖断言）单独放在
//     MemoryTargetTrackerTests.Walk.cpp（单文件不得超过 800 行），入口见 TestSupport 头。

#include "TestSupport.h"

#include "MemoryTargetTrackerTestSupport.h"

#include "../shared/evidence/memory_workbench/MemoryTargetTracker.h"

#include <cstdint>

namespace {

using ksword::memwb::Channel;
using ksword::memwb::HasChange;
using ksword::memwb::IsIdentityChange;
using ksword::memwb::IsPinnedAttachGeneration;
using ksword::memwb::kIdentityChangeMask;
using ksword::memwb::kPinnedAttachGenerationBit;
using ksword::memwb::MemoryTargetSession;
using ksword::memwb::MemoryTargetTracker;
using ksword::memwb::RevisionSnapshot;
using ksword::memwb::SameTarget;
using ksword::memwb::Scope;
using ksword::memwb::SessionError;
using ksword::memwb::SessionRevisions;
using ksword::memwb::TargetChange;
using ksword::memwb::Validate;
using Follow = ksword::memwb::MemoryTargetTracker::Follow;

// uint64 的最大值，用来检验计数器回绕。
constexpr std::uint64_t kMax64 = 0xFFFFFFFFFFFFFFFFULL;

// kPin：钉住代次的标记位（2^63），手算钉住代次时直接用它加小整数。
constexpr std::uint64_t kPin = 0x8000000000000000ULL;

// ------------------------------------------------------------
// 一、枚举数值、掩码辅助函数、初始状态。
// ------------------------------------------------------------
void TestEnumValuesAndMaskHelpers(KswordTests::Suite& suite) {
    // 变更位的数值会经 Qt 信号以整数形式传出，必须钉死。
    suite.expect(static_cast<std::uint32_t>(TargetChange::None) == 0U, L"tracker: None is 0");
    suite.expect(static_cast<std::uint32_t>(TargetChange::Scope) == 1U, L"tracker: Scope is 1");
    suite.expect(static_cast<std::uint32_t>(TargetChange::Process) == 2U, L"tracker: Process is 2");
    suite.expect(static_cast<std::uint32_t>(TargetChange::Channel) == 4U, L"tracker: Channel is 4");
    suite.expect(static_cast<std::uint32_t>(TargetChange::Ddma) == 8U, L"tracker: Ddma is 8");
    suite.expect(static_cast<std::uint32_t>(TargetChange::Bits) == 16U, L"tracker: Bits is 16");
    suite.expect(static_cast<std::uint32_t>(TargetChange::Policy) == 32U, L"tracker: Policy is 32");
    suite.expect(static_cast<std::uint32_t>(TargetChange::Reload) == 64U, L"tracker: Reload is 64");
    suite.expect(static_cast<std::uint32_t>(TargetChange::Rejected) == 128U, L"tracker: Rejected is 128");

    // 身份位掩码 = 1+2+4+8+16 = 31，不含 Policy/Reload/Rejected。
    suite.expect(static_cast<std::uint32_t>(kIdentityChangeMask) == 31U,
        L"tracker: the identity mask is the five identity bits only");

    // 五个身份位各自被识别为身份变化。
    suite.expect(IsIdentityChange(TargetChange::Scope), L"tracker: Scope is an identity change");
    suite.expect(IsIdentityChange(TargetChange::Process), L"tracker: Process is an identity change");
    suite.expect(IsIdentityChange(TargetChange::Channel), L"tracker: Channel is an identity change");
    suite.expect(IsIdentityChange(TargetChange::Ddma), L"tracker: Ddma is an identity change");
    suite.expect(IsIdentityChange(TargetChange::Bits), L"tracker: Bits is an identity change");

    // 另外四个值都不是身份变化：这是"Reload 是唯一不改身份的 bump"这条性质的前提。
    suite.expect(!IsIdentityChange(TargetChange::None), L"tracker: None is not an identity change");
    suite.expect(!IsIdentityChange(TargetChange::Policy), L"tracker: Policy is not an identity change");
    suite.expect(!IsIdentityChange(TargetChange::Reload), L"tracker: Reload is not an identity change");
    suite.expect(!IsIdentityChange(TargetChange::Rejected), L"tracker: Rejected is not an identity change");
    suite.expect(IsIdentityChange(TargetChange::Policy | TargetChange::Ddma),
        L"tracker: a mask that mixes Policy with an identity bit is an identity change");

    // 运算符与 HasChange。
    const TargetChange both = TargetChange::Process | TargetChange::Bits;
    suite.expect(static_cast<std::uint32_t>(both) == 18U, L"tracker: Process|Bits is 18");
    suite.expect(HasChange(both, TargetChange::Process), L"tracker: a mask contains one of its bits");
    suite.expect(HasChange(both, TargetChange::Bits), L"tracker: a mask contains its other bit");
    suite.expect(!HasChange(both, TargetChange::Scope), L"tracker: a mask lacks a bit it does not hold");
    suite.expect(HasChange(both, both), L"tracker: a mask contains itself");
    suite.expect(!HasChange(TargetChange::Process, both),
        L"tracker: a single bit does not contain a two-bit group");
    suite.expect(!HasChange(both, TargetChange::None), L"tracker: nothing is contained by checking None");
    suite.expect(!HasChange(TargetChange::None, TargetChange::None),
        L"tracker: checking None against None is false so empty checks cannot pass vacuously");
    TargetChange accumulated = TargetChange::None;
    accumulated |= TargetChange::Ddma;
    accumulated |= TargetChange::Policy;
    suite.expect(static_cast<std::uint32_t>(accumulated) == 40U, L"tracker: |= accumulates bits (8+32)");
    suite.expect((both & TargetChange::Bits) == TargetChange::Bits, L"tracker: & extracts a shared bit");
    suite.expect((both & TargetChange::Scope) == TargetChange::None, L"tracker: & of disjoint bits is None");

    // 钉住代次标记位：2^63，两侧各测一次。
    suite.expect(kPinnedAttachGenerationBit == 0x8000000000000000ULL, L"tracker: the pin bit is 2^63");
    suite.expect(IsPinnedAttachGeneration(0x8000000000000000ULL), L"tracker: 2^63 is a pinned generation");
    suite.expect(IsPinnedAttachGeneration(kMax64), L"tracker: the maximum value is a pinned generation");
    suite.expect(!IsPinnedAttachGeneration(0x7FFFFFFFFFFFFFFFULL),
        L"tracker: 2^63-1 is a dock generation");
    suite.expect(!IsPinnedAttachGeneration(0ULL), L"tracker: 0 is a dock generation");
}

void TestInitialState(KswordTests::Suite& suite) {
    const MemoryTargetTracker tracker;
    const MemoryTargetSession& session = tracker.Session();

    // 初始会话与默认构造的会话逐字段相同：故意无效，没选目标就不能读任何东西。
    suite.expect(session.scope == Scope::ProcessVirtual, L"tracker init: process scope");
    suite.expect(session.pid == 0U, L"tracker init: pid 0");
    suite.expect(session.processCreateTime100ns == 0ULL, L"tracker init: create time 0");
    suite.expect(session.attachGeneration == 0ULL, L"tracker init: attach generation 0");
    suite.expect(session.channel == Channel::UserMode, L"tracker init: least privileged channel");
    suite.expect(session.ddmaGeneration == 0ULL, L"tracker init: ddma generation 0");
    suite.expect(session.addressBits == 64U, L"tracker init: 64-bit");
    suite.expect(Validate(session) == SessionError::NeedsPid, L"tracker init: the session needs a pid");
    suite.expect(SameTarget(session, MemoryTargetSession()), L"tracker init: equals the default session");

    // 两个计数器从 0 开始；默认跟随 Dock；跟随 Dock 且范围=进程，所以 Dock 事件会改会话。
    suite.expect(tracker.Revisions().Source() == 0ULL, L"tracker init: source revision 0");
    suite.expect(tracker.Revisions().Content() == 0ULL, L"tracker init: content revision 0");
    suite.expect(tracker.FollowMode() == Follow::Dock, L"tracker init: follows the dock");
    suite.expect(tracker.WouldChangeOnDockAttach(), L"tracker init: dock events would change the session");

    // 传入初值：来源与内容各按位置对应。
    const MemoryTargetTracker restored(SessionRevisions(5, 9));
    suite.expect(restored.Revisions().Source() == 5ULL && restored.Revisions().Content() == 9ULL,
        L"tracker init: initial revisions are honored in order");
}

// ------------------------------------------------------------
// 二、Dock 附加/分离：重复调用幂等、代次/创建时间/位宽各自触发。
// ------------------------------------------------------------
void TestFollowAttachDetach(KswordTests::Suite& suite) {
    MemoryTargetTracker tracker;

    // 首次附加：pid 0->1234、创建时间 0->5、代次 0->7，位宽仍是 64，掩码恰为 Process。
    TargetChange mask = tracker.FollowAttach(1234, 5, 7, 64);
    suite.expect(mask == TargetChange::Process, L"attach: the first attach reports exactly Process");
    suite.expect(tracker.Session().pid == 1234U, L"attach: pid is recorded");
    suite.expect(tracker.Session().processCreateTime100ns == 5ULL, L"attach: create time is recorded");
    suite.expect(tracker.Session().attachGeneration == 7ULL, L"attach: generation is recorded");
    suite.expect(tracker.Session().addressBits == 64U, L"attach: width is recorded");
    suite.expect(Validate(tracker.Session()) == SessionError::None, L"attach: the session becomes valid");
    suite.expect(tracker.Revisions().Source() == 1ULL, L"attach: the source revision moves to 1");
    suite.expect(tracker.Revisions().Content() == 0ULL, L"attach: the content revision is untouched");

    // 同参数重复调用：返回 None 且不 bump。
    suite.expect(tracker.FollowAttach(1234, 5, 7, 64) == TargetChange::None,
        L"attach: repeating identical arguments returns None");
    suite.expect(tracker.Revisions().Source() == 1ULL, L"attach: repeating identical arguments does not bump");

    // 同进程重附加（只有代次变）：必须 bump，这就是"重附加后旧句柄上的页不可信"。
    mask = tracker.FollowAttach(1234, 5, 8, 64);
    suite.expect(mask == TargetChange::Process, L"attach: a re-attach of the same process reports Process");
    suite.expect(tracker.Revisions().Source() == 2ULL, L"attach: a re-attach with a new generation bumps");
    suite.expect(tracker.Session().attachGeneration == 8ULL, L"attach: the new generation is recorded");

    // 只有创建时间变（PID 被复用）：同样必须 bump。
    mask = tracker.FollowAttach(1234, 6, 8, 64);
    suite.expect(mask == TargetChange::Process, L"attach: a changed create time reports Process");
    suite.expect(tracker.Revisions().Source() == 3ULL, L"attach: pid reuse with another create time bumps");

    // 换另一个进程且位宽变成 32：掩码是 Process|Bits，只 bump 一次。
    mask = tracker.FollowAttach(4321, 9, 9, 32);
    suite.expect(mask == (TargetChange::Process | TargetChange::Bits),
        L"attach: a new 32-bit process reports Process and Bits together");
    suite.expect(tracker.Revisions().Source() == 4ULL,
        L"attach: two changed fields still bump the source revision once");
    suite.expect(tracker.Session().addressBits == 32U, L"attach: the 32-bit width is recorded");

    // 只有位宽变：掩码恰为 Bits。
    mask = tracker.FollowAttach(4321, 9, 9, 64);
    suite.expect(mask == TargetChange::Bits, L"attach: a width-only change reports exactly Bits");
    suite.expect(tracker.Revisions().Source() == 5ULL, L"attach: a width-only change bumps");

    // 分离：目标清空，进程位变；再次分离什么都不变。
    mask = tracker.FollowDetach();
    suite.expect(mask == TargetChange::Process, L"detach: clearing a 64-bit target reports Process");
    suite.expect(tracker.Session().pid == 0U, L"detach: pid returns to 0");
    suite.expect(tracker.Session().processCreateTime100ns == 0ULL, L"detach: create time returns to 0");
    suite.expect(tracker.Session().attachGeneration == 0ULL, L"detach: generation returns to 0");
    suite.expect(Validate(tracker.Session()) == SessionError::NeedsPid, L"detach: the session needs a pid again");
    suite.expect(tracker.Revisions().Source() == 6ULL, L"detach: clearing the target bumps");
    suite.expect(tracker.FollowDetach() == TargetChange::None, L"detach: detaching twice returns None");
    suite.expect(tracker.Revisions().Source() == 6ULL, L"detach: detaching twice does not bump");

    // 从 32 位目标分离：位宽回到 64，所以掩码带 Bits。
    suite.expect(tracker.FollowAttach(7, 1, 1, 32) == (TargetChange::Process | TargetChange::Bits),
        L"detach setup: attach a 32-bit process");
    suite.expect(tracker.FollowDetach() == (TargetChange::Process | TargetChange::Bits),
        L"detach: leaving a 32-bit target also reports the width change");
    suite.expect(tracker.Session().addressBits == 64U, L"detach: the width returns to 64");
}

// ------------------------------------------------------------
// 三、非法参数：一律 Rejected，状态完全不变，也没有悄悄记账。
// ------------------------------------------------------------
void TestRejectedArguments(KswordTests::Suite& suite) {
    MemoryTargetTracker tracker;
    suite.expect(tracker.FollowAttach(100, 1, 2, 64) == TargetChange::Process, L"reject setup: attach");
    const MemoryTargetSession before = tracker.Session();
    const RevisionSnapshot beforeRevisions = tracker.Revisions().Capture();

    // FollowAttach 的各类非法参数。
    suite.expect(tracker.FollowAttach(0, 1, 2, 64) == TargetChange::Rejected, L"reject: attach with pid 0");
    suite.expect(tracker.FollowAttach(100, 1, 2, 0) == TargetChange::Rejected, L"reject: attach with width 0");
    suite.expect(tracker.FollowAttach(100, 1, 2, 16) == TargetChange::Rejected, L"reject: attach with width 16");
    suite.expect(tracker.FollowAttach(100, 1, 2, 48) == TargetChange::Rejected, L"reject: attach with width 48");
    suite.expect(tracker.FollowAttach(100, 1, 2, 65) == TargetChange::Rejected, L"reject: attach with width 65");
    suite.expect(tracker.FollowAttach(100, 1, kPin, 64) == TargetChange::Rejected,
        L"reject: a dock generation equal to 2^63 would collide with pinned generations");
    suite.expect(tracker.FollowAttach(100, 1, kMax64, 64) == TargetChange::Rejected,
        L"reject: the maximum dock generation is rejected");

    // Pin 的非法参数。
    suite.expect(tracker.Pin(0, 1, 64) == TargetChange::Rejected, L"reject: pin with pid 0");
    suite.expect(tracker.Pin(100, 1, 0) == TargetChange::Rejected, L"reject: pin with width 0");
    suite.expect(tracker.Pin(100, 1, 33) == TargetChange::Rejected, L"reject: pin with width 33");

    // SetScope / SetChannel 的越界值。
    suite.expect(tracker.SetScope(static_cast<Scope>(3)) == TargetChange::Rejected,
        L"reject: scope value 3");
    suite.expect(tracker.SetScope(static_cast<Scope>(0xFFFFFFFFU)) == TargetChange::Rejected,
        L"reject: the largest scope value");
    suite.expect(tracker.SetChannel(static_cast<Channel>(4), 9) == TargetChange::Rejected,
        L"reject: channel value 4");
    suite.expect(tracker.SetChannel(static_cast<Channel>(0xFFFFFFFFU), 9) == TargetChange::Rejected,
        L"reject: the largest channel value");

    // 以上全部被拒后，会话与两个计数器都与拒绝之前逐项相同。
    suite.expect(SameTarget(tracker.Session(), before), L"reject: the session is unchanged after rejections");
    suite.expect(!tracker.Revisions().IsStale(beforeRevisions),
        L"reject: neither counter moved after rejections");
    suite.expect(tracker.FollowMode() == Follow::Dock, L"reject: a rejected pin did not switch to pinned");

    // 没有悄悄记账：被拒的 FollowAttach 若偷偷写了 Dock 记录，切到内核再切回进程时会露馅。
    suite.expect(tracker.SetScope(Scope::KernelVirtual) != TargetChange::Rejected, L"reject setup: kernel");
    suite.expect(tracker.FollowAttach(0, 0, 0, 64) == TargetChange::Rejected,
        L"reject: a rejected attach while following nothing");
    suite.expect(tracker.FollowAttach(555, 1, 1, 48) == TargetChange::Rejected,
        L"reject: a bad-width attach while in the kernel scope");
    suite.expect(tracker.SetScope(Scope::ProcessVirtual) != TargetChange::Rejected, L"reject setup: back");
    suite.expect(tracker.Session().pid == 100U,
        L"reject: rejected attaches left the dock record untouched (pid 100 survived)");
    suite.expect(tracker.Session().processCreateTime100ns == 1ULL && tracker.Session().attachGeneration == 2ULL,
        L"reject: the dock record's other fields also survived");

    // 钉住代次计数没被被拒的 Pin 消耗：第一个成功钉住拿到 2^63+1。
    suite.expect(tracker.Pin(0, 0, 64) == TargetChange::Rejected, L"reject: pin again with pid 0");
    suite.expect(tracker.Pin(200, 3, 64) == (TargetChange::Process | TargetChange::Policy),
        L"reject setup: a real pin");
    suite.expect(tracker.Session().attachGeneration == kPin + 1ULL,
        L"reject: rejected pins did not consume pinned generations");

    // 边界另一侧：Dock 代次 2^63-1 合法，被接受。
    MemoryTargetTracker boundary;
    suite.expect(boundary.FollowAttach(1, 0, 0x7FFFFFFFFFFFFFFFULL, 64) == TargetChange::Process,
        L"reject: dock generation 2^63-1 is accepted");
    suite.expect(boundary.Session().attachGeneration == 0x7FFFFFFFFFFFFFFFULL,
        L"reject: dock generation 2^63-1 is recorded in full");
    // 位宽 32 与 64 两个合法值都被接受。
    suite.expect(boundary.FollowAttach(1, 0, 1, 32) != TargetChange::Rejected, L"reject: width 32 is accepted");
    suite.expect(boundary.FollowAttach(1, 0, 1, 64) != TargetChange::Rejected, L"reject: width 64 is accepted");
}

// ------------------------------------------------------------
// 四、内核/物理范围：进程字段归零，Dock 事件不 bump。
// ------------------------------------------------------------
void TestKernelAndPhysicalScopes(KswordTests::Suite& suite) {
    MemoryTargetTracker tracker;
    suite.expect(tracker.FollowAttach(1234, 5, 7, 32) == (TargetChange::Process | TargetChange::Bits),
        L"scope setup: attach a 32-bit process");
    suite.expect(tracker.Revisions().Source() == 1ULL, L"scope setup: one bump so far");

    // 进程 -> 内核：范围、进程字段（pid/创建时间/代次归零）、位宽（32->64）三项都变。
    TargetChange mask = tracker.SetScope(Scope::KernelVirtual);
    suite.expect(mask == (TargetChange::Scope | TargetChange::Process | TargetChange::Bits),
        L"scope: process to kernel reports scope, process and width changes");
    suite.expect(tracker.Session().scope == Scope::KernelVirtual, L"scope: now the kernel scope");
    suite.expect(tracker.Session().pid == 0U, L"scope: the kernel session has pid 0");
    suite.expect(tracker.Session().processCreateTime100ns == 0ULL, L"scope: the kernel session has create time 0");
    suite.expect(tracker.Session().attachGeneration == 0ULL, L"scope: the kernel session has generation 0");
    suite.expect(tracker.Session().addressBits == 64U, L"scope: the kernel session is 64-bit");
    suite.expect(Validate(tracker.Session()) == SessionError::None, L"scope: the kernel session is valid");
    suite.expect(tracker.Revisions().Source() == 2ULL, L"scope: switching scope bumps once");
    suite.expect(!tracker.WouldChangeOnDockAttach(), L"scope: dock events no longer change a kernel session");

    // 内核范围下 Dock 的附加/分离只记账：None 且不 bump，会话不动。
    const MemoryTargetSession kernelSession = tracker.Session();
    suite.expect(tracker.FollowAttach(99, 1, 2, 64) == TargetChange::None,
        L"scope: attaching under the kernel scope returns None");
    suite.expect(tracker.FollowDetach() == TargetChange::None,
        L"scope: detaching under the kernel scope returns None");
    suite.expect(tracker.FollowAttach(55, 3, 4, 32) == TargetChange::None,
        L"scope: attaching again under the kernel scope returns None");
    suite.expect(tracker.Revisions().Source() == 2ULL, L"scope: dock events under the kernel scope never bump");
    suite.expect(SameTarget(tracker.Session(), kernelSession), L"scope: the kernel session did not move");

    // 内核 -> 物理：只有范围变（进程字段本来就是零）。
    mask = tracker.SetScope(Scope::Physical);
    suite.expect(mask == TargetChange::Scope, L"scope: kernel to physical reports exactly Scope");
    suite.expect(tracker.Revisions().Source() == 3ULL, L"scope: kernel to physical bumps");
    suite.expect(tracker.FollowAttach(56, 4, 5, 64) == TargetChange::None,
        L"scope: attaching under the physical scope returns None");
    suite.expect(tracker.Revisions().Source() == 3ULL, L"scope: dock events under the physical scope never bump");

    // 物理 -> 进程：记账的 Dock 进程（56,4,5,64）在这里露面；位宽 64 与零值一致，所以不含 Bits。
    mask = tracker.SetScope(Scope::ProcessVirtual);
    suite.expect(mask == (TargetChange::Scope | TargetChange::Process),
        L"scope: physical to process surfaces the recorded dock process");
    suite.expect(tracker.Session().pid == 56U && tracker.Session().processCreateTime100ns == 4ULL
            && tracker.Session().attachGeneration == 5ULL,
        L"scope: the dock record kept during the kernel scope is the one that appears");
    suite.expect(tracker.Revisions().Source() == 4ULL, L"scope: physical to process bumps once");
    suite.expect(tracker.WouldChangeOnDockAttach(), L"scope: dock events change a process session again");

    // 同范围重复调用：None 且不 bump。
    suite.expect(tracker.SetScope(Scope::ProcessVirtual) == TargetChange::None,
        L"scope: repeating the same scope returns None");
    suite.expect(tracker.Revisions().Source() == 4ULL, L"scope: repeating the same scope does not bump");

    // 内核范围下无目标也是合法会话（pid 必须为 0）。
    MemoryTargetTracker fresh;
    suite.expect(fresh.SetScope(Scope::KernelVirtual) == TargetChange::Scope,
        L"scope: a fresh tracker switching to kernel reports exactly Scope");
    suite.expect(Validate(fresh.Session()) == SessionError::None, L"scope: a fresh kernel session is valid");
    suite.expect(fresh.SetScope(Scope::ProcessVirtual) == TargetChange::Scope,
        L"scope: back to process with no dock target reports exactly Scope");
    suite.expect(Validate(fresh.Session()) == SessionError::NeedsPid,
        L"scope: a process session with no dock target needs a pid");
}

// ------------------------------------------------------------
// 五、通道与 DDMA 代次：不联动、代次归零、观察只在 Ddma 通道有效。
// ------------------------------------------------------------
void TestChannelAndDdma(KswordTests::Suite& suite) {
    MemoryTargetTracker tracker;
    suite.expect(tracker.FollowAttach(1234, 5, 7, 64) == TargetChange::Process, L"channel setup: attach");
    suite.expect(tracker.Revisions().Source() == 1ULL, L"channel setup: one bump so far");

    // 切到 R0：传入的代次对非 Ddma 通道无意义，会话里仍是 0。
    TargetChange mask = tracker.SetChannel(Channel::StandardDriver, 99);
    suite.expect(mask == TargetChange::Channel, L"channel: switching to R0 reports exactly Channel");
    suite.expect(tracker.Session().channel == Channel::StandardDriver, L"channel: the channel is recorded");
    suite.expect(tracker.Session().ddmaGeneration == 0ULL,
        L"channel: a ddma generation passed for a non-ddma channel is ignored");
    suite.expect(tracker.Revisions().Source() == 2ULL, L"channel: switching channel bumps");
    suite.expect(tracker.Session().scope == Scope::ProcessVirtual, L"channel: the scope was not touched");

    // 同参数重复：None 且不 bump（非 Ddma 通道换一个无意义的代次也是 None）。
    suite.expect(tracker.SetChannel(Channel::StandardDriver, 99) == TargetChange::None,
        L"channel: repeating the same channel returns None");
    suite.expect(tracker.SetChannel(Channel::StandardDriver, 100) == TargetChange::None,
        L"channel: a different ignored generation on a non-ddma channel still returns None");
    suite.expect(tracker.Revisions().Source() == 2ULL, L"channel: repeats do not bump");

    // 切到 Ddma：代次取传入值，掩码含 Channel 与 Ddma。
    mask = tracker.SetChannel(Channel::Ddma, 5);
    suite.expect(mask == (TargetChange::Channel | TargetChange::Ddma),
        L"channel: switching to ddma with generation 5 reports Channel and Ddma");
    suite.expect(tracker.Session().ddmaGeneration == 5ULL, L"channel: the ddma generation is recorded");
    suite.expect(tracker.Revisions().Source() == 3ULL, L"channel: Channel and Ddma together bump once");

    // 同通道同代次：None；同通道不同代次：只有 Ddma 位。
    suite.expect(tracker.SetChannel(Channel::Ddma, 5) == TargetChange::None,
        L"channel: repeating ddma with the same generation returns None");
    suite.expect(tracker.SetChannel(Channel::Ddma, 6) == TargetChange::Ddma,
        L"channel: ddma with a new generation reports exactly Ddma");
    suite.expect(tracker.Revisions().Source() == 4ULL, L"channel: a new ddma generation bumps");

    // ObserveDdma：通道=Ddma 时有效，代次相同为 None，不同为 Ddma 并 bump。
    suite.expect(tracker.ObserveDdma(6) == TargetChange::None, L"observe: an unchanged generation returns None");
    suite.expect(tracker.Revisions().Source() == 4ULL, L"observe: an unchanged generation does not bump");
    suite.expect(tracker.ObserveDdma(7) == TargetChange::Ddma, L"observe: a changed generation reports Ddma");
    suite.expect(tracker.Session().ddmaGeneration == 7ULL, L"observe: the new generation is recorded");
    suite.expect(tracker.Revisions().Source() == 5ULL, L"observe: a changed generation bumps");
    // 代次回到 0 也是一次变化（暂存扇区被还原再重置），不能因为"0 看着像初值"而漏掉。
    suite.expect(tracker.ObserveDdma(0) == TargetChange::Ddma, L"observe: a change to generation 0 is a change");
    suite.expect(tracker.Revisions().Source() == 6ULL, L"observe: a change to generation 0 bumps");
    suite.expect(tracker.ObserveDdma(0) == TargetChange::None, L"observe: generation 0 repeated returns None");

    // 离开 Ddma：代次归零，掩码含 Ddma（7 -> 0 的那一次变化）。先把代次设回 7 再离开。
    suite.expect(tracker.ObserveDdma(7) == TargetChange::Ddma, L"leave setup: generation 7");
    mask = tracker.SetChannel(Channel::Hvm, 123);
    suite.expect(mask == (TargetChange::Channel | TargetChange::Ddma),
        L"channel: leaving ddma reports Channel and the ddma generation reset");
    suite.expect(tracker.Session().ddmaGeneration == 0ULL, L"channel: leaving ddma zeroes the generation");

    // 通道不是 Ddma 时观察无效：None、不 bump、会话里仍是 0。
    const std::uint64_t sourceBefore = tracker.Revisions().Source();
    suite.expect(tracker.ObserveDdma(55) == TargetChange::None, L"observe: ignored when the channel is not ddma");
    suite.expect(tracker.Revisions().Source() == sourceBefore, L"observe: an ignored observation does not bump");
    suite.expect(tracker.Session().ddmaGeneration == 0ULL, L"observe: an ignored observation does not leak in");

    // 旧代次不会"复活"：回到 Ddma 只认这次传入的代次，哪怕之前观察过 55。
    mask = tracker.SetChannel(Channel::Ddma, 9);
    suite.expect(mask == (TargetChange::Channel | TargetChange::Ddma), L"channel: back to ddma with generation 9");
    suite.expect(tracker.Session().ddmaGeneration == 9ULL,
        L"channel: only the generation passed on re-entry is used, not an old observation");
    // 回到 Ddma 且代次恰为 0：只有 Channel 位。
    suite.expect(tracker.SetChannel(Channel::UserMode, 0) == (TargetChange::Channel | TargetChange::Ddma),
        L"channel: leaving ddma again resets");
    suite.expect(tracker.SetChannel(Channel::Ddma, 0) == TargetChange::Channel,
        L"channel: entering ddma with generation 0 reports only Channel");
}

// ------------------------------------------------------------
// 六、范围与通道不联动：没有任何自动回退。
// ------------------------------------------------------------
void TestScopeAndChannelAreIndependent(KswordTests::Suite& suite) {
    MemoryTargetTracker tracker;
    suite.expect(tracker.SetChannel(Channel::Hvm, 0) == TargetChange::Channel, L"independent setup: Hvm");
    suite.expect(tracker.SetScope(Scope::KernelVirtual) == TargetChange::Scope,
        L"independent: switching scope reports only Scope");
    suite.expect(tracker.Session().channel == Channel::Hvm, L"independent: switching scope keeps the channel");
    suite.expect(tracker.SetScope(Scope::Physical) == TargetChange::Scope, L"independent: kernel to physical");
    suite.expect(tracker.Session().channel == Channel::Hvm, L"independent: the channel survives again");

    // 跟踪器不裁决通道是否适合范围：R3 + 物理它照收，不会悄悄换成别的通道。
    // "R3 不支持物理"这类判断属于 MemoryChannelGate，由界面层报红。
    suite.expect(tracker.SetChannel(Channel::UserMode, 0) == TargetChange::Channel,
        L"independent: the tracker accepts a channel the gate would grey out");
    suite.expect(tracker.Session().channel == Channel::UserMode && tracker.Session().scope == Scope::Physical,
        L"independent: the requested channel is kept exactly, nothing is substituted");
    suite.expect(tracker.SetScope(Scope::ProcessVirtual) == TargetChange::Scope,
        L"independent: switching scope back reports only Scope");
    suite.expect(tracker.Session().channel == Channel::UserMode, L"independent: still the same channel");
}

// ------------------------------------------------------------
// 七、钉住与回到跟随：代次手算、同身份只改 Policy、钉住不受 Dock 牵动。
// ------------------------------------------------------------
void TestPinAndUnpin(KswordTests::Suite& suite) {
    MemoryTargetTracker tracker;
    suite.expect(tracker.FollowAttach(1234, 5, 7, 64) == TargetChange::Process, L"pin setup: dock attach");
    suite.expect(tracker.Revisions().Source() == 1ULL, L"pin setup: one bump so far");

    // 钉住 Dock 正在跟随的同一个进程：只改 Policy，不 bump，沿用 Dock 的代次 7。
    TargetChange mask = tracker.Pin(1234, 5, 64);
    suite.expect(mask == TargetChange::Policy, L"pin: pinning the dock's own process reports exactly Policy");
    suite.expect(tracker.Revisions().Source() == 1ULL, L"pin: pinning the dock's own process does not bump");
    suite.expect(tracker.Session().attachGeneration == 7ULL,
        L"pin: the dock's generation is adopted so the session does not move");
    suite.expect(tracker.FollowMode() == Follow::Pinned, L"pin: the mode is pinned");
    suite.expect(!tracker.WouldChangeOnDockAttach(), L"pin: dock events no longer change a pinned session");

    // 钉住期间 Dock 的任何附加/分离都只记账。
    suite.expect(tracker.FollowAttach(1234, 5, 8, 64) == TargetChange::None,
        L"pin: a dock re-attach of the pinned process returns None");
    suite.expect(tracker.FollowAttach(777, 3, 9, 64) == TargetChange::None,
        L"pin: a dock attach of another process returns None");
    suite.expect(tracker.Revisions().Source() == 1ULL, L"pin: dock events while pinned never bump");
    suite.expect(tracker.Session().pid == 1234U && tracker.Session().attachGeneration == 7ULL,
        L"pin: the pinned session did not follow the dock");

    // 同一个进程再钉一次：None，且不消耗钉住代次。
    suite.expect(tracker.Pin(1234, 5, 64) == TargetChange::None, L"pin: pinning the same process again is None");

    // 回到跟随：Dock 现在是 777，会话从 1234 变到 777，掩码含 Process 与 Policy，bump 一次。
    mask = tracker.Unpin();
    suite.expect(mask == (TargetChange::Process | TargetChange::Policy),
        L"unpin: returning to a different dock process reports Process and Policy");
    suite.expect(tracker.Session().pid == 777U && tracker.Session().attachGeneration == 9ULL,
        L"unpin: the session now follows the dock's 777 with generation 9");
    suite.expect(tracker.Revisions().Source() == 2ULL, L"unpin: a changed target bumps once");
    suite.expect(tracker.FollowMode() == Follow::Dock, L"unpin: the mode is follow again");
    suite.expect(tracker.Unpin() == TargetChange::None, L"unpin: unpinning while following returns None");
    suite.expect(tracker.Revisions().Source() == 2ULL, L"unpin: a repeated unpin does not bump");
}

void TestPinGenerations(KswordTests::Suite& suite) {
    // 钉住一个 Dock 没有的进程：代次 = 2^63 + 1，掩码 Process|Policy，bump。
    MemoryTargetTracker tracker;
    suite.expect(tracker.FollowAttach(1234, 5, 7, 64) == TargetChange::Process, L"pin gen setup: attach");
    TargetChange mask = tracker.Pin(888, 4, 64);
    suite.expect(mask == (TargetChange::Process | TargetChange::Policy),
        L"pin gen: pinning another process reports Process and Policy");
    suite.expect(tracker.Session().pid == 888U && tracker.Session().processCreateTime100ns == 4ULL,
        L"pin gen: the pinned process is the session target");
    suite.expect(tracker.Session().attachGeneration == 0x8000000000000001ULL,
        L"pin gen: the first pinned generation is 2^63 + 1");
    suite.expect(IsPinnedAttachGeneration(tracker.Session().attachGeneration),
        L"pin gen: a pinned generation carries the pin bit");
    suite.expect(tracker.Revisions().Source() == 2ULL, L"pin gen: a changed target bumps");
    suite.expect(tracker.Pin(888, 4, 64) == TargetChange::None, L"pin gen: the same pin again is None");
    suite.expect(tracker.Session().attachGeneration == 0x8000000000000001ULL,
        L"pin gen: an idempotent pin does not consume a generation");

    // 钉住 -> 换钉另一个进程：没有 Policy（模式没变），代次 2^63 + 2。
    mask = tracker.Pin(999, 5, 64);
    suite.expect(mask == TargetChange::Process, L"pin gen: re-pinning another process reports exactly Process");
    suite.expect(tracker.Session().attachGeneration == 0x8000000000000002ULL,
        L"pin gen: the second pinned generation is 2^63 + 2");

    // 同 pid、创建时间变（PID 复用）：算另一个目标，代次 2^63 + 3。
    mask = tracker.Pin(999, 6, 64);
    suite.expect(mask == TargetChange::Process, L"pin gen: the same pid with another create time is a new target");
    suite.expect(tracker.Session().attachGeneration == 0x8000000000000003ULL,
        L"pin gen: the third pinned generation is 2^63 + 3");

    // 同进程但位宽变：Process|Bits，代次 2^63 + 4。
    mask = tracker.Pin(999, 6, 32);
    suite.expect(mask == (TargetChange::Process | TargetChange::Bits),
        L"pin gen: the same process with another width reports Process and Bits");
    suite.expect(tracker.Session().attachGeneration == 0x8000000000000004ULL,
        L"pin gen: the fourth pinned generation is 2^63 + 4");
    suite.expect(tracker.Revisions().Source() == 5ULL, L"pin gen: three more changed targets bumped three times");

    // 回到跟随：Dock 是 1234（32 位变回 64 位），会话 Process|Bits|Policy。
    mask = tracker.Unpin();
    suite.expect(mask == (TargetChange::Process | TargetChange::Bits | TargetChange::Policy),
        L"unpin: leaving a pinned 32-bit process reports Process, Bits and Policy");
    suite.expect(tracker.Session().pid == 1234U && tracker.Session().attachGeneration == 7ULL,
        L"unpin: the dock's generation comes back and does not carry the pin bit");
    suite.expect(!IsPinnedAttachGeneration(tracker.Session().attachGeneration),
        L"unpin: a followed session never carries a pinned generation");

    // 创建时间 0（身份未锚定）按精确相等比较：Dock 是 (4, ct 0)，钉 (4, ct 0) 同身份沿用 Dock 代次；
    // 钉 (4, ct 5) 不同身份，走新代次。
    MemoryTargetTracker weak;
    suite.expect(weak.FollowAttach(4, 0, 3, 64) == TargetChange::Process, L"pin weak setup: attach");
    suite.expect(weak.Pin(4, 0, 64) == TargetChange::Policy,
        L"pin weak: an unanchored create time 0 equal to the dock's is the same identity");
    suite.expect(weak.Session().attachGeneration == 3ULL, L"pin weak: the dock's generation is adopted");
    MemoryTargetTracker weak2;
    suite.expect(weak2.FollowAttach(4, 0, 3, 64) == TargetChange::Process, L"pin weak2 setup: attach");
    suite.expect(weak2.Pin(4, 5, 64) == (TargetChange::Process | TargetChange::Policy),
        L"pin weak: a known create time never matches an unanchored one");
    suite.expect(weak2.Session().attachGeneration == kPin + 1ULL, L"pin weak: the new target gets a fresh generation");

    // 与 Dock 同 pid/创建时间但位宽不同：不是同身份，走新代次。
    MemoryTargetTracker widthDiff;
    suite.expect(widthDiff.FollowAttach(4, 7, 3, 64) == TargetChange::Process, L"pin width setup: attach");
    suite.expect(widthDiff.Pin(4, 7, 32) == (TargetChange::Process | TargetChange::Bits | TargetChange::Policy),
        L"pin width: a different width is not the dock's identity");

    // Dock 没附加时钉住：新代次；之后 Dock 才附加，钉住的不动。
    MemoryTargetTracker empty;
    suite.expect(empty.Pin(31, 2, 64) == (TargetChange::Process | TargetChange::Policy),
        L"pin empty: pinning with nothing attached to the dock");
    suite.expect(empty.Session().attachGeneration == kPin + 1ULL, L"pin empty: a fresh pinned generation");
    suite.expect(empty.FollowAttach(31, 2, 1, 64) == TargetChange::None,
        L"pin empty: a later dock attach of the same process is only bookkeeping");
    suite.expect(empty.Session().attachGeneration == kPin + 1ULL,
        L"pin empty: the pinned generation was not replaced by the dock's");
}

void TestPinInOtherScopes(KswordTests::Suite& suite) {
    // 内核范围下钉住：会话不变（内核会话没有进程字段），只有 Policy，不 bump。
    MemoryTargetTracker tracker;
    suite.expect(tracker.SetScope(Scope::KernelVirtual) == TargetChange::Scope, L"pin kernel setup: kernel");
    const MemoryTargetSession kernelSession = tracker.Session();
    suite.expect(tracker.Revisions().Source() == 1ULL, L"pin kernel setup: one bump so far");
    suite.expect(tracker.Pin(500, 1, 64) == TargetChange::Policy,
        L"pin kernel: pinning under the kernel scope reports exactly Policy");
    suite.expect(tracker.Revisions().Source() == 1ULL, L"pin kernel: pinning under the kernel scope does not bump");
    suite.expect(SameTarget(tracker.Session(), kernelSession), L"pin kernel: the kernel session is unchanged");

    // 切回进程范围：钉住的 500 露面，代次是这次钉住消耗的 2^63 + 1。
    TargetChange mask = tracker.SetScope(Scope::ProcessVirtual);
    suite.expect(mask == (TargetChange::Scope | TargetChange::Process),
        L"pin kernel: back to process surfaces the pinned process");
    suite.expect(tracker.Session().pid == 500U && tracker.Session().attachGeneration == kPin + 1ULL,
        L"pin kernel: the pinned process and its generation appear");
    suite.expect(tracker.Revisions().Source() == 2ULL, L"pin kernel: the scope switch bumps once");

    // 钉住后到内核范围再回到跟随：内核会话不变，只有 Policy，不 bump。
    suite.expect(tracker.SetScope(Scope::KernelVirtual) == (TargetChange::Scope | TargetChange::Process),
        L"unpin kernel setup: to the kernel scope");
    const std::uint64_t sourceBefore = tracker.Revisions().Source();
    suite.expect(tracker.Unpin() == TargetChange::Policy,
        L"unpin kernel: unpinning under the kernel scope reports exactly Policy");
    suite.expect(tracker.Revisions().Source() == sourceBefore,
        L"unpin kernel: unpinning under the kernel scope does not bump");

    // 钉住期间 Dock 分离再回到跟随：会话变成"无目标"。
    MemoryTargetTracker detached;
    suite.expect(detached.FollowAttach(8, 1, 1, 64) == TargetChange::Process, L"unpin detach setup: attach");
    suite.expect(detached.Pin(8, 1, 64) == TargetChange::Policy, L"unpin detach setup: pin the same");
    suite.expect(detached.FollowDetach() == TargetChange::None, L"unpin detach: the dock detaches while pinned");
    suite.expect(detached.Session().pid == 8U, L"unpin detach: the pinned session survives the dock detach");
    suite.expect(detached.Unpin() == (TargetChange::Process | TargetChange::Policy),
        L"unpin detach: following a detached dock clears the target");
    suite.expect(detached.Session().pid == 0U, L"unpin detach: no target after following a detached dock");
}

// ------------------------------------------------------------
// 八、Reload 与 NoteContentChanged：两个计数器互不串位。
// ------------------------------------------------------------
void TestReloadAndContent(KswordTests::Suite& suite) {
    MemoryTargetTracker tracker;
    suite.expect(tracker.FollowAttach(1234, 5, 7, 64) == TargetChange::Process, L"reload setup: attach");
    const MemoryTargetSession before = tracker.Session();

    // Reload：来源代次 +1，返回 Reload，会话身份纹丝不动，内容代次不动。
    suite.expect(tracker.Reload() == TargetChange::Reload, L"reload: returns exactly Reload");
    suite.expect(tracker.Revisions().Source() == 2ULL, L"reload: the source revision moves");
    suite.expect(tracker.Revisions().Content() == 0ULL, L"reload: the content revision is untouched");
    suite.expect(SameTarget(tracker.Session(), before), L"reload: the session identity is unchanged");
    suite.expect(tracker.Reload() == TargetChange::Reload, L"reload: a second reload also bumps");
    suite.expect(tracker.Revisions().Source() == 3ULL, L"reload: every reload bumps, there is no coalescing");

    // NoteContentChanged：只动内容代次。
    const RevisionSnapshot snapshot = tracker.Revisions().Capture();
    tracker.NoteContentChanged();
    suite.expect(tracker.Revisions().Content() == 1ULL, L"content: the content revision moves to 1");
    suite.expect(tracker.Revisions().Source() == 3ULL, L"content: the source revision is untouched");
    suite.expect(SameTarget(tracker.Session(), before), L"content: the session is unchanged");
    suite.expect(tracker.Revisions().IsStale(snapshot), L"content: a snapshot from before the edit is stale");
    tracker.NoteContentChanged();
    tracker.NoteContentChanged();
    suite.expect(tracker.Revisions().Content() == 3ULL, L"content: three notes give 3");

    // 没有目标时 Reload 照样 bump：整窗重读与目标是否有效无关。
    MemoryTargetTracker empty;
    suite.expect(empty.Reload() == TargetChange::Reload, L"reload: works with no target");
    suite.expect(empty.Revisions().Source() == 1ULL, L"reload: bumps even with no target");

    // 快照语义：重读之后，重读之前捕获的快照陈旧；新捕获的新鲜。
    MemoryTargetTracker snap;
    const RevisionSnapshot old = snap.Revisions().Capture();
    suite.expect(snap.Reload() == TargetChange::Reload, L"snapshot setup: reload");
    suite.expect(snap.Revisions().IsStale(old), L"snapshot: a reload makes an older snapshot stale");
    suite.expect(!snap.Revisions().IsStale(snap.Revisions().Capture()), L"snapshot: a fresh capture is fresh");
}

// ------------------------------------------------------------
// 九、计数器回绕：2^64-1 之后旧快照仍判陈旧。
// ------------------------------------------------------------
// 独立会话关闭必须清身份、保留钉住策略，并使旧读取快照陈旧。
void TestClearPinnedTarget(KswordTests::Suite& suite) {
    MemoryTargetTracker tracker;
    tracker.FollowAttach(100, 10, 1, 64);
    tracker.Pin(200, 20, 32);
    tracker.SetChannel(Channel::StandardDriver, 0);
    const auto old = tracker.Revisions().Capture();
    const auto changed = tracker.ClearPinnedTarget();
    suite.expect(HasChange(changed, TargetChange::Process), L"clear: target identity changed");
    suite.expect(tracker.Session().pid == 0, L"clear: pid removed");
    suite.expect(tracker.Session().processCreateTime100ns == 0, L"clear: creation time removed");
    suite.expect(tracker.Session().attachGeneration == 0, L"clear: attachment generation removed");
    suite.expect(tracker.FollowMode() == Follow::Pinned, L"clear: stays independent");
    suite.expect(!tracker.WouldChangeOnDockAttach(), L"clear: ignores Dock changes");
    suite.expect(tracker.Session().channel == Channel::StandardDriver, L"clear: keeps channel");
    suite.expect(tracker.Revisions().Source() == old.source + 1, L"clear: source advances once");
    suite.expect(tracker.Revisions().Content() == old.content, L"clear: content revision unchanged");
    suite.expect(tracker.Revisions().IsStale(old), L"clear: old snapshot stale");
    const auto empty = tracker.Revisions().Capture();
    suite.expect(tracker.ClearPinnedTarget() == TargetChange::None, L"clear: empty close is idempotent");
    suite.expect(!tracker.Revisions().IsStale(empty), L"clear: repeat close keeps revision");
    // 主动恢复普通跟随后也不得复活已经清除的旧 Dock 记录。
    tracker.Unpin();
    suite.expect(tracker.Session().pid == 0, L"clear: no old Dock target resurrected");
}

void TestWraparound(KswordTests::Suite& suite) {
    // 来源代次在最大值：一次 FollowAttach 让它回绕到 0，旧快照陈旧，内容代次不受影响。
    MemoryTargetTracker tracker((SessionRevisions(kMax64, kMax64)));
    const RevisionSnapshot atMax = tracker.Revisions().Capture();
    suite.expect(tracker.FollowAttach(10, 1, 1, 64) == TargetChange::Process, L"wrap setup: attach");
    suite.expect(tracker.Revisions().Source() == 0ULL, L"wrap: the source revision wraps from the maximum to 0");
    suite.expect(tracker.Revisions().Content() == kMax64, L"wrap: the content revision did not move");
    suite.expect(tracker.Revisions().IsStale(atMax), L"wrap: a snapshot from before the wrap is stale");

    // 内容代次回绕。
    tracker.NoteContentChanged();
    suite.expect(tracker.Revisions().Content() == 0ULL, L"wrap: the content revision wraps to 0");
    suite.expect(tracker.Revisions().Source() == 0ULL, L"wrap: noting content did not move the source revision");
    suite.expect(tracker.Revisions().IsStale(atMax), L"wrap: still stale after both counters wrapped");

    // Reload 也能回绕：来源代次从最大值经 Reload 回到 0，旧快照仍陈旧。
    MemoryTargetTracker reload((SessionRevisions(kMax64, 0)));
    const RevisionSnapshot beforeReload = reload.Revisions().Capture();
    suite.expect(reload.Reload() == TargetChange::Reload, L"wrap reload setup");
    suite.expect(reload.Revisions().Source() == 0ULL, L"wrap: a reload wraps the source revision");
    suite.expect(reload.Revisions().IsStale(beforeReload), L"wrap: a snapshot from before a wrapping reload is stale");
}

} // namespace

int RunMemwbTargetTrackerTests() {
    KswordTests::Suite suite(L"MEMWB target tracker");
    TestEnumValuesAndMaskHelpers(suite);
    TestInitialState(suite);
    TestFollowAttachDetach(suite);
    TestRejectedArguments(suite);
    TestKernelAndPhysicalScopes(suite);
    TestChannelAndDdma(suite);
    TestScopeAndChannelAreIndependent(suite);
    TestPinAndUnpin(suite);
    TestPinGenerations(suite);
    TestPinInOtherScopes(suite);
    TestReloadAndContent(suite);
    TestWraparound(suite);
    TestClearPinnedTarget(suite);
    RunTrackerRandomWalk(suite);
    suite.report();
    return suite.failures();
}
