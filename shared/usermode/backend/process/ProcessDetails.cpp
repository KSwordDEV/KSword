#include "ProcessDetails.h"

#include <algorithm>

namespace ks::r3::process {
namespace {
std::wstring Wide(const std::string& text) {
    if (text.empty()) return {};
    const int count = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (count <= 0) return L"文本解码失败";
    std::wstring result(static_cast<std::size_t>(count), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), count);
    return result;
}

const wchar_t* FeatureText(ks::process::ProcessFeatureState state) {
    using S = ks::process::ProcessFeatureState;
    switch (state) {
    case S::NotAllowed: return L"不适用";
    case S::Disabled: return L"已禁用";
    case S::Enabled: return L"已启用";
    case S::EnabledPermanent: return L"已启用（永久）";
    default: return L"查询失败或不支持";
    }
}

const wchar_t* DpiText(ks::process::ProcessDpiAwarenessLevel level) {
    using D = ks::process::ProcessDpiAwarenessLevel;
    switch (level) {
    case D::Unaware: return L"不感知";
    case D::SystemAware: return L"系统";
    case D::PerMonitorAware: return L"每监视器";
    case D::PerMonitorAwareV2: return L"每监视器 V2";
    case D::UnawareGdiScaled: return L"不感知（GDI 缩放）";
    default: return L"查询失败或不支持";
    }
}
} // namespace

std::uint32_t DetailDemandForColumns(const std::vector<ProcessFieldId>& columns) {
    using C = ProcessFieldId;
    using namespace ks::process;
    std::uint32_t demand = ProcessDetailDemand::None;
    for (const C column : columns) {
        switch (column) {
        case C::GpuEngine: demand |= ProcessDetailDemand::GpuEngine; break;
        case C::GpuDedicatedMemory: case C::GpuSharedMemory: demand |= ProcessDetailDemand::GpuMemory; break;
        case C::PackageName: demand |= ProcessDetailDemand::PackageName; break;
        case C::Description: demand |= ProcessDetailDemand::FileDescription; break;
        case C::DpiAwareness: demand |= ProcessDetailDemand::DpiAwareness; break;
        case C::UacVirtualization: demand |= ProcessDetailDemand::UacVirtualization; break;
        case C::DataExecutionPrevention: case C::ControlFlowGuard: case C::HardwareStackProtection:
            demand |= ProcessDetailDemand::MitigationPolicy; break;
        case C::JobObject: demand |= ProcessDetailDemand::JobObject; break;
        case C::EnterpriseContext: demand |= ProcessDetailDemand::EnterpriseContext; break;
        default: break;
        }
    }
    return demand;
}

void ApplyProcessDetailRecord(ProcessSnapshotRow& row, const ks::process::ProcessRecord& record) {
    // Refuse enrichment from another incarnation of the same recyclable PID.
    if (row.processId != record.pid || row.r0KernelOnly ||
        (row.creationTime100ns != 0 && row.creationTime100ns != record.creationTime100ns)) return;
    using C = ProcessFieldId;
    const auto put = [&row](C column, const std::wstring& text) {
        row.detailTexts[static_cast<std::uint8_t>(column)] = text;
    };
    const bool kernel = row.processId <= 4;
    const auto textOrReason = [kernel](const std::string& text) {
        return text.empty() ? (kernel ? std::wstring(L"不适用") : std::wstring(L"访问受限或查询失败")) : Wide(text);
    };
    if (!record.imagePath.empty()) {
        row.imagePath = Wide(record.imagePath);
        put(C::Path, row.imagePath);
    }
    put(C::CommandLine, textOrReason(record.commandLine));
    put(C::User, record.userName.empty() && kernel ? L"NT AUTHORITY\\SYSTEM" : textOrReason(record.userName));
    put(C::Signature, kernel && record.imagePath.empty() ? L"不适用" : textOrReason(record.signatureState));
    put(C::Description, record.fileDescription.empty() ? L"无描述" : Wide(record.fileDescription));
    put(C::ProcessType, textOrReason(record.architectureText));
    put(C::PackageName, record.packageNameKnown ? (record.packageFullName.empty() ? L"无程序包" : Wide(record.packageFullName)) : L"访问受限或查询失败");
    put(C::IsAdmin, kernel ? L"不适用" : (record.isAdminKnown ? (record.isAdmin ? L"是" : L"否") : L"令牌访问受限"));
    put(C::PowerThrottling, record.efficiencyModeSupported ? (record.efficiencyModeEnabled ? L"已启用" : L"已禁用") : L"查询失败或不支持");
    put(C::Status, record.processStateKnown ? (record.processSuspended ? L"已挂起" : L"运行中") : L"未知");
    put(C::JobObject, record.jobObjectKnown ? (record.inJobObject ? L"是" : L"否") : L"访问受限或查询失败");
    put(C::UacVirtualization, FeatureText(record.uacVirtualizationState));
    put(C::DataExecutionPrevention, FeatureText(record.dataExecutionPreventionState));
    put(C::ControlFlowGuard, FeatureText(record.controlFlowGuardState));
    put(C::HardwareStackProtection, FeatureText(record.hardwareStackProtectionState));
    put(C::DpiAwareness, DpiText(record.dpiAwarenessLevel));
    put(C::EnterpriseContext, textOrReason(record.enterpriseContextText));
    put(C::PplLevel, record.protectionLevelKnown ? Wide(record.protectionLevelText) : L"访问受限或查询失败");
    if (record.protectionLevelKnown) {
        put(C::Protection, Wide(record.protectionLevelText));
        const auto level = record.protectionLevel;
        put(C::Ppl, level == 0U || level == 2U || level == 3U || level == 4U || level == 6U || level == 8U ? L"是" : L"否");
    }
    wchar_t percent[32]{};
    ::swprintf_s(percent, L"%.1f%%", record.gpuPercent);
    put(C::Gpu, record.gpuUsageKnown ? percent : L"采样预热或计数器不支持");
    put(C::GpuEngine, record.gpuUsageKnown ?
        (record.gpuEngineText.empty() ? L"无活动引擎" : Wide(record.gpuEngineText)) : L"采样预热或计数器不支持");
}

} // namespace ks::r3::process
