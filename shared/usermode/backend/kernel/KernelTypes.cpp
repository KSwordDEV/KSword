#include "KernelTypes.h"

namespace ks::r3::kernel {

std::wstring ToDisplayName(const KernelFeatureId id) {
    // The switch is deliberately exhaustive for current retained KernelDock
    // entries. Unknown future values fall through to a safe generic label.
    switch (id) {
    case KernelFeatureId::ObjectNamespaceOverview: return L"对象命名空间";
    case KernelFeatureId::ObjectDirectoryRecursive: return L"目录递归";
    case KernelFeatureId::NamedPipe: return L"命名管道";
    case KernelFeatureId::BaseNamedObjects: return L"BaseNamedObjects";
    case KernelFeatureId::SymbolicLink: return L"符号链接";
    case KernelFeatureId::DeviceDriverObjects: return L"设备与驱动对象";
    case KernelFeatureId::ObjectTypeMatrix: return L"对象类型矩阵";
    case KernelFeatureId::CommunicationEndpoint: return L"通信端点";
    case KernelFeatureId::AtomTable: return L"原子表遍历";
    case KernelFeatureId::NtQueryLegacy: return L"历史 NtQuery";
    case KernelFeatureId::Ssdt: return L"SSDT 遍历";
    case KernelFeatureId::ShadowSsdt: return L"SSSDT 解析";
    case KernelFeatureId::InlineHook: return L"Inline Hook 检测 & 摘除";
    case KernelFeatureId::IatEatHook: return L"IAT/EAT 钩子检测";
    case KernelFeatureId::DynData: return L"动态偏移";
    case KernelFeatureId::DriverStatus: return L"驱动状态";
    case KernelFeatureId::CallbackIntercept: return L"驱动回调";
    case KernelFeatureId::CallbackEnumeration: return L"回调遍历";
    case KernelFeatureId::KernelExecutableMemory: return L"内核可执行内存";
    case KernelFeatureId::KernelMemoryEvidence: return L"内核内存证据";
    case KernelFeatureId::ProcessCrossView: return L"进程 CrossView";
    case KernelFeatureId::ThreadCrossView: return L"线程 CrossView";
    case KernelFeatureId::DriverIntegrity: return L"驱动完整性";
    case KernelFeatureId::KernelCpuIntegrity: return L"CPU/IDT 完整性";
    case KernelFeatureId::CpuHardwareSnapshot: return L"CPU 硬件快照";
    case KernelFeatureId::PhysicalMemoryLayout: return L"物理内存布局";
    case KernelFeatureId::MutationAudit: return L"内核修改审计";
    case KernelFeatureId::KeyboardHotkeys: return L"键盘热键枚举";
    case KernelFeatureId::KeyboardHooks: return L"键盘钩子枚举";
    case KernelFeatureId::DynDataCapabilities: return L"DynData 能力";
    case KernelFeatureId::MinifilterBypassPids: return L"Minifilter 放行 PID";
    case KernelFeatureId::KernelTimerDpc: return L"KTIMER/DPC";
    case KernelFeatureId::IoctlRegistry: return L"IOCTL 派遣表";
    case KernelFeatureId::PdbProfileStatus: return L"PDB Profile 状态";
    case KernelFeatureId::CidTableSummary: return L"CID 表摘要";
    case KernelFeatureId::IpcSummary: return L"IPC 汇总";
    case KernelFeatureId::HookAuditSummary: return L"Hook 审计摘要";
    default: return L"未知内核功能";
    }
}

std::wstring BackendToDisplayName(const KernelFeatureBackend backend) {
    // Keep labels short because this text is shown in the feature list and in
    // the detail panel. The enum remains the source of truth for routing.
    switch (backend) {
    case KernelFeatureBackend::UserModeNative: return L"R3 Native";
    case KernelFeatureBackend::ArkDriverClient: return L"ArkDriverClient";
    case KernelFeatureBackend::Hybrid: return L"R3 + ArkDriverClient";
    default: return L"Unknown";
    }
}

} // namespace ks::r3::kernel
