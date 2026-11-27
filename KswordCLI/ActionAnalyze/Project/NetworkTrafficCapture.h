#pragma once

#include "ProjectNetworkEvidence.h"

#include <atomic>
#include <memory>

namespace Ksword::ActionAnalyze {

// RawSocket复用网络Tab服务；ExistingWfp只读既有ring，不重置全局开关、加载驱动或静默切源。
// 支持回环的新WFP采集器仅提交入站可回退的真实IP字节；此用户态入口不据Ready推断双向覆盖。
enum class NetworkTrafficBackend { RawSocket, ExistingWfp };

struct NetworkTrafficCapturePlan {
    std::string sampleId; // 已存在的原采样 UUID，采集器绝不另建采样。
    std::string bootId; // 本次 Windows 启动身份，用于来源时钟绑定。
    std::uint32_t pid = 0; // 原请求根；之后仅通过AppendTarget显式扩展同一来源的筛选成员。
    std::uint64_t creationFileTime = 0; // 整段持有同一进程句柄并验证请求身份。
    std::uint32_t durationMs = 0; // 会话为0时由外部Close结束；独立同步入口仍要求100..60000ms。
    NetworkTrafficBackend backend = NetworkTrafficBackend::RawSocket; // 显式来源，无静默回退。
    bool keepAliveForAppendedTargets = false; // true时暂时无活动成员也等待Close/取消/时长；false在全部成员退出时结束。
};

struct NetworkTrafficCaptureReceipt {
    std::optional<NetworkTrafficBackend> requestedBackend; // 构造时冻结的显式来源选择，不代表来源已就绪或实际覆盖。
    ProjectResult status; // 采集或归档错误；来源启动失败单独以 reason 标识。
    ProjectNetworkCheckpoint checkpoint; // 最后成功发布的网络检查点。
    // 终态原因使用稳定机器值，区分未启动、启动失败、来源失败、取消和正常停止。
    // 典型值包括 not-started、invalid-plan、target-identity-failed、source-unavailable、
    // duration-elapsed、cancelled、target-exited、stopped、archive-failed。
    std::string reason;
    std::vector<std::string> diagnostics; // 真实服务状态或驱动错误，不作为完成证据。
    std::uint64_t packets = 0; // 已提交且核验的网络记录数。
    std::uint64_t capturedBytes = 0; // 实际已提交 IP 层字节，不含 ETW 计数。
    std::uint64_t queueDropped = 0; // 本所有者有界队列丢弃数。
    std::uint64_t unsupportedPackets = 0; // 无法表达的方向、地址或 ALE 元数据记录数。
    std::uint64_t sourceGap = 0; // WFP cursor 的已知缺口。
    bool sourceReady = false; // 至少一次观察到真实采集源已就绪。
    bool cleanupConfirmed = false; // 本次拥有的 R3 线程完成 join；只读 WFP 无启停责任。
    std::vector<ProjectNetworkTargetWindow> targets; // 当前已准入实例及各自生命周期，不代表逐包强证据。
};

// 每次追加独立返回准入结果；失败不污染正在采集的主回执，不隐式停止其它成员。
struct NetworkTrafficTargetReceipt {
    ProjectResult status; // 参数、会话阶段、OpenProcess、身份和存活复核的具体错误。
    std::uint32_t pid = 0; // 调用方请求的目标PID。
    std::uint64_t creationFileTime = 0; // 调用方请求的强身份创建时间。
    std::uint64_t startUtc = 0; // 成功时实际接纳时刻；重复请求保持首次值。
    bool accepted = false; // 已加入本会话且在本次复核时仍存活。
    bool alreadyPresent = false; // 同一PID/创建时间重复请求，不开新窗口或重启来源。
    std::string reason; // added、already-present或明确失败机器值。
};

// 原API worker可在同一项目写租约内串行服务本会话；不建立第二writer或后台写档线程。
// project与cancel必须存活至Close及析构；全部方法由持有该项目的同一worker线程调用。
class NetworkTrafficSession final {
public:
    // 冻结原sample、目标和来源；构造仅保存参数，不打开项目或启动来源。
    NetworkTrafficSession(ProjectDocument& project, NetworkTrafficCapturePlan plan,
        const std::atomic_bool& cancel);
    // 析构兜底关闭来源；所有者应显式Close后读取最终回执，并保持项目仍然打开。
    ~NetworkTrafficSession();
    NetworkTrafficSession(const NetworkTrafficSession&) = delete;
    NetworkTrafficSession& operator=(const NetworkTrafficSession&) = delete;

    // 初始化已有sample/绑定、持有同实例对象并启动来源；返回是否已接受本次启动。
    // Raw Socket异步就绪，由后续Poll更新Receipt().sourceReady；重复调用不重启。
    bool Start();
    // 由原writer worker在接管Ready/ACK前同步调用。只接纳PID+创建时间匹配且仍存活的真实对象。
    // 不启动服务/线程/writer，不回补准入前流量；来源尚在异步准备时也可追加，sourceReady单独回读。
    // 失败写入Receipt().diagnostics，不覆盖来源终态或撤销其它成员。
    bool AppendTarget(std::uint32_t pid, std::uint64_t creationFileTime);
    // 需要逐项准入回执的兼容入口，与AppendTarget使用完全相同的准入实现。
    NetworkTrafficTargetReceipt AddTarget(std::uint32_t pid, std::uint64_t creationFileTime);
    // 不等待数据、不sleep、不join；最多读取一批并在调用线程同步分段归档。
    // reason非空表示已请求停止，调用方须Close完成清退及终态发布。
    void Poll();
    // 停止本次来源，排空固定截止范围并提交终态；同步join只发生在此，重复调用幂等。
    void Close();
    // 返回本会话实时回执的只读引用；Close之后才是最终状态，引用不授予并发读取能力。
    const NetworkTrafficCaptureReceipt& Receipt() const;

private:
    struct State; // 隔离原抓包服务、进程句柄及邮箱，公开头不引入网络实现依赖。
    std::unique_ptr<State> state_; // 独占本次来源生命周期，借用原项目和取消位。
};

// 同步归档工作线程调用：借用项目写租约，内部复用现有抓包服务，取消后排空并发布原采样检查点。
// 调用前应由端侧明确授权接口级抓包的可见范围。所有者不配置限速、隔离、防火墙或 HTTPS 代理。
// 此兼容入口仍要求100..60000ms；内部通过NetworkTrafficSession驱动，不复制采集实现。
NetworkTrafficCaptureReceipt CaptureNetworkTraffic(ProjectDocument& project,
    const NetworkTrafficCapturePlan& plan, const std::atomic_bool& cancelled);

} // namespace Ksword::ActionAnalyze
