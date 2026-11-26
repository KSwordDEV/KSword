#pragma once

#include "ArchivedEvidenceGraph.h"
#include "../Project/ProjectNativeExecution.h"

namespace Ksword::ActionAnalyze::Detection {

// NativeSectionMapAssociation：节映射范围与独立原生指令观察的一致性候选，不建立执行因果。
struct NativeSectionMapAssociation {
    EvidenceRef mapping; // 映射原包的项目、采样、来源及 raw 坐标。
    std::string mappingSha256; // 当前映射所在已核验 API 段的 SHA-256。
    Evidence::ApiSectionMapFieldsV1 fields; // 原映射请求、实际输出、有效位及 API 原时钟。
    std::uint32_t actorPid = 0; // 映射原包的源 PID，创建代次在 fields 中。
    std::uint64_t nativeSegmentOrdinal = 0; // 独立 raw-native 链中的原段号。
    std::uint64_t nativeRecordSequence = 0; // 原生观察的归档记录序号。
    std::string nativeSha256; // 已核验原生段的 SHA-256。
    std::string observation; // 原样保留进入尝试或指令完成，二者不混用。
    std::uint64_t instructionAddress = 0; // 实际指令起点，不采用 nextInstructionAddress。
    std::uint32_t tid = 0; // 原生观察实际报告的执行线程，不从节句柄补造。
    std::uint64_t threadCreationFileTime = 0; // 原生线程创建代次。
    std::optional<std::uint64_t> observedQpc; // 原生观察的原 QPC，不跨来源排序。
    std::optional<std::uint64_t> nativeQpcFrequency; // 原生文档报告的原频率。
    bool sourceAuthenticated = false; // 档案完整性不认证历史生产者。
    bool regionVersionVerified = false; // 未核验映射到执行期间的区域或内容版本。
    bool causalityConfirmed = false; // 同进程同范围不证明映射导致本次执行。
    bool commonClockVerified = false; // API 与原生来源无共同启动期时钟证明。
    bool writeObserved = false; // 本关联不要求也不证明写入。
    bool aliasPropagationVerified = false; // 原节句柄不提供节对象或共享别名身份。
};

// AssociateNativeSectionMap：输入同采样已核验图页中的 mapping/evidence、该页摘要和原生段。
// scope 限定项目及采样；mappingSha256 为 API 段摘要，nativeSegmentOrdinal 为原生段坐标。
// 只有精确 Accepted 映射、完整稳定进程代次和实际指令落入实际映射半开区间才返回候选。
// 不匹配返回空，不访问进程、不比较两路 QPC、不把请求范围或节句柄升级为写入/别名证据。
std::optional<NativeSectionMapAssociation> AssociateNativeSectionMap(
    const SampleScope& scope,
    const EvidenceRef& evidence,
    const ArchivedGraphRecord& mapping,
    std::string_view mappingSha256,
    const ArchivedNativeExecution& execution,
    std::uint64_t nativeSegmentOrdinal);

// AAIM1成功Allocate/Protect的实际范围与独立执行观察；不宣称MEM_PRIVATE、仍存活或调用导致执行。
struct NativeMemoryRangeAssociation {
    EvidenceRef request; // 原内存生命周期请求的来源坐标。
    std::string requestSha256; // 已核验API段摘要。
    Evidence::ApiMemoryLifecycleFieldsV1 fields; // 请求与实际输出均保留，不用请求范围填补输出。
    std::uint64_t nativeSegmentOrdinal = 0; // 独立原生段号。
    std::uint64_t instructionAddress = 0; // 实际观察的指令起点，不使用下一RIP。
    std::uint32_t tid = 0; // 原生真实执行线程编号。
    std::uint64_t threadCreationFileTime = 0; // 同一线程的创建代次。
    std::string observation; // execution-enter-attempt或instruction-completed原值。
};

// 输入同采样已核验原请求及原生段；仅匹配成功实际输出、稳定强实例和实际指令半开区间。
// Free/Unmap、失败、缺输出或代次不匹配返回空；不比较跨源QPC、不访问目标、不生成控制权。
std::optional<NativeMemoryRangeAssociation> AssociateNativeMemoryRange(const SampleScope& scope,
    const EvidenceRef& evidence, const ArchivedGraphRecord& request, std::string_view requestSha256,
    const ArchivedNativeExecution& execution, std::uint64_t nativeSegmentOrdinal);

} // namespace Ksword::ActionAnalyze::Detection
