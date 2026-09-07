#pragma once

// F-03 稳定对象身份。
//
// 规则：
//   * 进程 = 启动标识 + PID + 创建时间。缺创建时间只能得到"弱"身份。
//   * 线程绑定所属进程实例，并保留可用的线程创建标识。
//   * 驱动、文件、句柄、连接各自记录可获得的生命周期身份。
//   * 地址、名字、裸 PID 都不能单独作为跨会话主键。
//   * 身份不足时结果是 Candidate，绝不自动升级成 Confirmed。
//   * 统一门槛：任一侧 strength() == Unusable 时，所有 Match* 最强只给 Candidate。
//     matcher 不得比 strength()/crossSessionKey() 更乐观 —— 后两者说"身份不足、不
//     发主键"时，前者不能说"确定是同一个"。矛盾证据仍然可以判 NoMatch。

#include "LosslessValue.h"

#include <cstdint>
#include <string>
#include <vector>

namespace Ksword::Evidence {

enum class ObjectKind {
    Unknown,
    Process,
    Thread,
    Driver,
    Module,
    File,
    Handle,
    Connection,
    Device,
    Service,
};

const char* ObjectKindName(ObjectKind kind) noexcept;

// 匹配结论。Candidate 表示"可能是同一个，但证据不足以确定"。
enum class MatchResult {
    NoMatch,    // 有足够证据判定不是同一个
    Candidate,  // 关键字段缺失或只有弱证据
    Confirmed,  // 生命周期身份完整且一致
};

const char* MatchResultName(MatchResult result) noexcept;

// 身份强度。用于 UI 标注"关联弱"。
enum class IdentityStrength {
    Unusable,  // 连弱主键都构不成
    Weak,      // 只有 PID/名字/地址一类可复用的标识
    Strong,    // 带生命周期标识（创建时间 / 文件 ID / 观察区间）
};

const char* IdentityStrengthName(IdentityStrength strength) noexcept;

// ---------------------------------------------------------------------------
// 进程实例
// ---------------------------------------------------------------------------
struct ProcessInstanceId final {
    std::string bootId;              // 启动标识；跨启动不可用裸 PID 匹配
    OptionalU64 pid;
    OptionalU64 createTime100ns;     // 缺失即关联弱
    OptionalU64 eprocessAddress;     // 仅作本次采集的辅助证据，不参与跨启动匹配
    std::string imageName;           // 辅助显示，不是主键

    IdentityStrength strength() const noexcept;

    // 跨会话主键。身份不足时返回空串 —— 调用方必须据此拒绝当成确定对象。
    std::string crossSessionKey() const;
};

MatchResult MatchProcessInstance(const ProcessInstanceId& a, const ProcessInstanceId& b) noexcept;

// ---------------------------------------------------------------------------
// 线程实例
// ---------------------------------------------------------------------------
struct ThreadInstanceId final {
    ProcessInstanceId process;   // 线程必须绑定进程实例
    OptionalU64 tid;
    OptionalU64 createTime100ns;
    OptionalU64 ethreadAddress;

    IdentityStrength strength() const noexcept;
    std::string crossSessionKey() const;
};

MatchResult MatchThreadInstance(const ThreadInstanceId& a, const ThreadInstanceId& b) noexcept;

// ---------------------------------------------------------------------------
// 驱动 / 模块实例
// ---------------------------------------------------------------------------
// X-04：加载模块、DriverObject、DeviceObject、磁盘服务配置是四种不同的东西，
// 不要求一对一对应，因此这里只描述"加载模块实例"。
struct DriverInstanceId final {
    std::string bootId;
    std::string imagePath;          // 归一化后的路径；同名不同版本要靠下面的字段区分
    OptionalU64 imageBase;          // 本次加载的基址，跨启动不可比
    OptionalU64 imageSize;
    OptionalU64 timeDateStamp;      // PE 头身份
    OptionalU64 checksum;
    std::string pdbSignature;       // RSDS GUID+Age，最强的映像身份
    OptionalU64 loadOrderIndex;

    IdentityStrength strength() const noexcept;
    std::string crossSessionKey() const;
};

MatchResult MatchDriverInstance(const DriverInstanceId& a, const DriverInstanceId& b) noexcept;

// ---------------------------------------------------------------------------
// 文件身份
// ---------------------------------------------------------------------------
struct FileIdentity final {
    std::string path;               // 同路径不同文件必须靠 volumeSerial+fileId 区分
    OptionalU64 volumeSerial;
    std::string fileId;             // 128 位 FileId 的无损文本表示
    OptionalU64 sizeBytes;
    OptionalU64 lastWriteUtc100ns;
    std::string contentHash;        // 内容身份；同一串字节可以存在于多个路径

    IdentityStrength strength() const noexcept;

    // 两种键，前缀不同不会互撞：
    //   "file"         = (volumeSerial, fileId)   —— 文件对象身份，硬链接共享
    //   "file-content" = (contentHash, 归一化 path) —— 只有内容时的退化键
    // 内容键必须带路径：同哈希异路径是"同样的字节"，不是"同一个文件对象"（F-03）。
    std::string crossSessionKey() const;
};

MatchResult MatchFileIdentity(const FileIdentity& a, const FileIdentity& b) noexcept;

// ---------------------------------------------------------------------------
// 句柄
// ---------------------------------------------------------------------------
struct HandleIdentity final {
    ProcessInstanceId owner;    // 句柄值只在所属进程实例内有意义
    OptionalU64 handleValue;
    OptionalU64 objectAddress;  // 地址会复用，只作本次辅助证据
    std::string typeName;

    IdentityStrength strength() const noexcept;
    std::string crossSessionKey() const;
};

MatchResult MatchHandleIdentity(const HandleIdentity& a, const HandleIdentity& b) noexcept;

// ---------------------------------------------------------------------------
// 网络连接
// ---------------------------------------------------------------------------
// 相同五元组在不同时段是不同连接，因此身份必须带观察区间。
struct ConnectionIdentity final {
    std::string bootId;
    std::uint32_t protocol = 0;     // IPPROTO_*
    std::string localAddress;       // 规范化后的文本（v4/v6）
    std::uint16_t localPort = 0;
    std::string remoteAddress;
    std::uint16_t remotePort = 0;
    OptionalU64 observedFirstUtc100ns;
    OptionalU64 observedLastUtc100ns;
    ProcessInstanceId owner;        // 可能未知

    IdentityStrength strength() const noexcept;
    std::string fiveTupleKey() const;
    std::string crossSessionKey() const;
};

// 相同五元组但观察区间不相交 -> NoMatch（不同连接）。
// 区间缺失 -> Candidate。
// Confirmed 还要求：两侧 bootId 非空且相等（跨启动保护），且所属进程匹配为
// Confirmed —— 端口在同一次启动内也会被下一个进程重新绑上（F-03）。
MatchResult MatchConnectionIdentity(const ConnectionIdentity& a, const ConnectionIdentity& b) noexcept;

// ---------------------------------------------------------------------------
// 通用引用：给导航与证据引用使用（F-12 / G-01）。
// ---------------------------------------------------------------------------
struct ObjectRef final {
    ObjectKind kind = ObjectKind::Unknown;
    std::string key;             // crossSessionKey()，空表示身份不足
    IdentityStrength strength = IdentityStrength::Unusable;
    std::string displayText;
    std::string evidenceId;      // 产生该引用的 envelope

    bool navigable() const noexcept { return !key.empty() && strength != IdentityStrength::Unusable; }
};

ObjectRef MakeProcessRef(const ProcessInstanceId& id, std::string evidenceId);
ObjectRef MakeThreadRef(const ThreadInstanceId& id, std::string evidenceId);
ObjectRef MakeDriverRef(const DriverInstanceId& id, std::string evidenceId);
ObjectRef MakeFileRef(const FileIdentity& id, std::string evidenceId);
ObjectRef MakeHandleRef(const HandleIdentity& id, std::string evidenceId);
ObjectRef MakeConnectionRef(const ConnectionIdentity& id, std::string evidenceId);

} // namespace Ksword::Evidence
