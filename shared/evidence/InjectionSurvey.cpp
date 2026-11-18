#include "InjectionSurvey.h"

#include <algorithm>
#include <unordered_map>
#include <utility>

namespace Ksword::Evidence {
namespace {

// 路径比较统一走这一个归一化：小写 + 反斜杠。两个来源给的路径大小写经常不同
// （加载器给 PEB 里的原串，映射查询给设备路径转换后的串），逐字符比会产生
// 大量假"名称不一致"。
std::string NormalizePath(const std::string& path) {
    std::string out;
    out.reserve(path.size());
    for (const char ch : path) {
        char c = ch;
        if (c == '/') {
            c = '\\';
        }
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
        out.push_back(c);
    }
    return out;
}

std::string FileNameOf(const std::string& path) {
    const std::size_t slash = path.find_last_of("\\/");
    return slash == std::string::npos ? path : path.substr(slash + 1U);
}

// 两个路径是不是指向同一个文件。设备路径（\Device\HarddiskVolume3\...）与
// DOS 路径（C:\...）无法互相换算，所以前缀不同但文件名与尾部一致时判"相容"，
// 不判"不一致" —— 否则每一个模块都会报一次假不一致。
bool PathsCompatible(const std::string& a, const std::string& b) {
    if (a.empty() || b.empty()) {
        return true;  // 有一侧没取到就没有矛盾可言，缺失由别的判据表达
    }
    const std::string na = NormalizePath(a);
    const std::string nb = NormalizePath(b);
    if (na == nb) {
        return true;
    }
    // 尾部包含：C:\windows\system32\ntdll.dll 与
    // \device\harddiskvolume3\windows\system32\ntdll.dll
    const std::string* longer = na.size() >= nb.size() ? &na : &nb;
    const std::string* shorter = na.size() >= nb.size() ? &nb : &na;
    // 去掉短串的盘符（"c:"），再看长串是否以剩余部分结尾。
    std::string tail = *shorter;
    if (tail.size() >= 2U && tail[1U] == ':') {
        tail = tail.substr(2U);
    }
    if (tail.empty()) {
        return false;
    }
    if (longer->size() >= tail.size() &&
        longer->compare(longer->size() - tail.size(), tail.size(), tail) == 0) {
        return true;
    }
    return FileNameOf(na) == FileNameOf(nb) && !FileNameOf(na).empty();
}

void AddUnique(std::vector<std::string>& list, const std::string& value) {
    if (value.empty()) {
        return;
    }
    if (std::find(list.begin(), list.end(), value) == list.end()) {
        list.push_back(value);
    }
}

std::string HexText(std::uint64_t value) {
    static const char* const kDigits = "0123456789ABCDEF";
    std::string out = "0x";
    bool started = false;
    for (int shift = 60; shift >= 0; shift -= 4) {
        const auto nibble = static_cast<std::size_t>((value >> shift) & 0xFULL);
        if (nibble != 0U || started || shift == 0) {
            out.push_back(kDigits[nibble]);
            started = true;
        }
    }
    return out;
}

std::string DecText(std::uint64_t value) {
    if (value == 0U) {
        return "0";
    }
    std::string out;
    while (value != 0U) {
        out.push_back(static_cast<char>('0' + static_cast<int>(value % 10U)));
        value /= 10U;
    }
    std::reverse(out.begin(), out.end());
    return out;
}

void AddFact(std::vector<std::string>& facts, const char* key, const std::string& value) {
    facts.push_back(std::string(key) + "=" + value);
}

bool OutcomeIsSuccess(const CollectionOutcome& outcome) noexcept {
    return outcome.status == CollectionStatus::Success;
}

// ImageDiff 的 limitationKeys 里混着两类完全不同的东西，不能一股脑当缺口：
//   * "这些字节根本不存在可用的磁盘参考" —— 零填充、节间隙、DVRT 位点、重定位
//     无法归一化。谁来比都比不了；它**定义**了"已覆盖范围"的边界，不是一次失败。
//     现代系统 DLL 基本都有 DVRT 位点，把它当缺口会让每一次扫描都"范围已破"，
//     四态在生产里又退化成三态。
//   * "我打算比、但没比成" —— 读不到、没采集、命中条目上限、模块已过期、参考
//     解析失败。这类是真的把声明的范围弄破了，必须压制"未发现差异"。
bool ImageLimitationIsScopeDefining(const std::string& key) noexcept {
    return key == "integrity.limitation.excludedNotComparable" ||
           key == "integrity.limitation.emptyCompareSet" ||
           key == "integrity.limitation.relocationUnsupportedTypes" ||
           key == "integrity.limitation.relocationDirectoryMissing" ||
           key == "integrity.limitation.relocationDirectoryUnbacked" ||
           key == "integrity.limitation.relocationDirectoryMalformed" ||
           key == "integrity.limitation.relocationsStripped";
}

} // namespace

// ---------------------------------------------------------------------------
// 名称表
// ---------------------------------------------------------------------------

const char* SurveyModeName(const SurveyMode mode) noexcept {
    switch (mode) {
    case SurveyMode::Fast: return "Fast";
    case SurveyMode::Deep: return "Deep";
    }
    return "Fast";
}

const char* ProcessArchitectureName(const ProcessArchitecture architecture) noexcept {
    switch (architecture) {
    case ProcessArchitecture::Unknown: return "Unknown";
    case ProcessArchitecture::X64: return "X64";
    case ProcessArchitecture::Wow64: return "Wow64";
    case ProcessArchitecture::X86Native: return "X86Native";
    case ProcessArchitecture::Arm64: return "Arm64";
    case ProcessArchitecture::Arm64Ec: return "Arm64Ec";
    }
    return "Unknown";
}

const char* CollectorArchitectureName(const CollectorArchitecture architecture) noexcept {
    switch (architecture) {
    case CollectorArchitecture::Unknown: return "Unknown";
    case CollectorArchitecture::Native64: return "Native64";
    case CollectorArchitecture::Wow64: return "Wow64";
    }
    return "Unknown";
}

const char* ModuleEnumerationTrustName(const ModuleEnumerationTrust trust) noexcept {
    switch (trust) {
    case ModuleEnumerationTrust::Unknown: return "Unknown";
    case ModuleEnumerationTrust::Trusted: return "Trusted";
    case ModuleEnumerationTrust::FilterIgnoredUnderWow64: return "FilterIgnoredUnderWow64";
    }
    return "Unknown";
}

ModuleEnumerationTrust EvaluateModuleEnumerationTrust(
    const CollectorArchitecture collector,
    const ProcessArchitecture target) noexcept {
    if (collector == CollectorArchitecture::Wow64) {
        // 过滤参数被忽略，拿到的永远只是 32 位视图 —— 与目标是什么架构无关。
        return ModuleEnumerationTrust::FilterIgnoredUnderWow64;
    }
    if (collector == CollectorArchitecture::Native64 &&
        target != ProcessArchitecture::Unknown) {
        return ModuleEnumerationTrust::Trusted;
    }
    return ModuleEnumerationTrust::Unknown;
}

const char* ExecuteProtectionName(const ExecuteProtection protection) noexcept {
    switch (protection) {
    case ExecuteProtection::Unknown: return "Unknown";
    case ExecuteProtection::NotExecutable: return "NotExecutable";
    case ExecuteProtection::Execute: return "Execute";
    case ExecuteProtection::ExecuteRead: return "ExecuteRead";
    case ExecuteProtection::ExecuteReadWrite: return "ExecuteReadWrite";
    case ExecuteProtection::ExecuteWriteCopy: return "ExecuteWriteCopy";
    }
    return "Unknown";
}

bool ExecuteProtectionIsExecutable(const ExecuteProtection protection) noexcept {
    switch (protection) {
    case ExecuteProtection::Execute:
    case ExecuteProtection::ExecuteRead:
    case ExecuteProtection::ExecuteReadWrite:
    case ExecuteProtection::ExecuteWriteCopy:
        return true;
    case ExecuteProtection::Unknown:
    case ExecuteProtection::NotExecutable:
        return false;
    }
    return false;
}

ProtectionFacts ClassifyWin32Protection(const OptionalU64& rawProtect) noexcept {
    ProtectionFacts facts;
    facts.rawValue = rawProtect;
    if (!rawProtect.present) {
        // 没给原始值就是未知。这里绝不能默认成 NotExecutable —— 那会把
        // "没查到权限"伪装成"这块内存不可执行"。
        return facts;
    }

    const auto raw = static_cast<std::uint32_t>(rawProtect.value & 0xFFFFFFFFULL);
    facts.guard = (raw & kWin32PageGuard) != 0U;

    switch (raw & kWin32ProtectBaseMask) {
    case kWin32PageNoAccess:
        facts.execute = ExecuteProtection::NotExecutable;
        facts.noAccess = true;
        break;
    case kWin32PageReadOnly:
        facts.execute = ExecuteProtection::NotExecutable;
        facts.readable = true;
        break;
    case kWin32PageReadWrite:
        facts.execute = ExecuteProtection::NotExecutable;
        facts.readable = true;
        facts.writable = true;
        break;
    case kWin32PageWriteCopy:
        facts.execute = ExecuteProtection::NotExecutable;
        facts.readable = true;
        facts.writable = true;
        facts.copyOnWrite = true;
        break;
    case kWin32PageExecute:
        facts.execute = ExecuteProtection::Execute;
        break;
    case kWin32PageExecuteRead:
        facts.execute = ExecuteProtection::ExecuteRead;
        facts.readable = true;
        break;
    case kWin32PageExecuteReadWrite:
        facts.execute = ExecuteProtection::ExecuteReadWrite;
        facts.readable = true;
        facts.writable = true;
        break;
    case kWin32PageExecuteWriteCopy:
        facts.execute = ExecuteProtection::ExecuteWriteCopy;
        facts.readable = true;
        facts.writable = true;
        facts.copyOnWrite = true;
        break;
    default:
        // 低字节不是任何已知基本值：看不懂。既不能当可执行也不能当不可执行。
        facts.unrecognizedBase = true;
        facts.execute = ExecuteProtection::Unknown;
        break;
    }
    return facts;
}

RegionProtection ToRegionProtection(const ProtectionFacts& facts) noexcept {
    RegionProtection protection;
    protection.readable = facts.readable;
    protection.writable = facts.writable;
    protection.executable = ExecuteProtectionIsExecutable(facts.execute);
    protection.copyOnWrite = facts.copyOnWrite;
    protection.guard = facts.guard;
    protection.noAccess = facts.noAccess;
    protection.rawValue = facts.rawValue;
    return protection;
}

const char* RegionCodeClassName(const RegionCodeClass codeClass) noexcept {
    switch (codeClass) {
    case RegionCodeClass::Unknown: return "Unknown";
    case RegionCodeClass::NotCommitted: return "NotCommitted";
    case RegionCodeClass::NonExecutable: return "NonExecutable";
    case RegionCodeClass::ImageExecutable: return "ImageExecutable";
    case RegionCodeClass::PrivateExecutable: return "PrivateExecutable";
    case RegionCodeClass::MappedExecutable: return "MappedExecutable";
    }
    return "Unknown";
}

bool IsDynamicCodeCandidate(const RegionCodeClass codeClass) noexcept {
    return codeClass == RegionCodeClass::PrivateExecutable ||
           codeClass == RegionCodeClass::MappedExecutable;
}

ProtectionFacts EffectiveProtection(const RegionRecord& record) noexcept {
    if (record.protection.rawValue.present) {
        return ClassifyWin32Protection(record.protection.rawValue);
    }
    const RegionProtection& p = record.protection;
    ProtectionFacts facts;
    const bool anyFlag = p.readable || p.writable || p.executable || p.copyOnWrite ||
                         p.guard || p.noAccess;
    if (!anyFlag) {
        // 全默认 = 来源一字未填。那是未知，不是"不可执行"。
        return facts;
    }
    facts.readable = p.readable;
    facts.writable = p.writable;
    facts.copyOnWrite = p.copyOnWrite;
    facts.guard = p.guard;
    facts.noAccess = p.noAccess;
    if (p.executable) {
        facts.execute = p.writable ? ExecuteProtection::ExecuteReadWrite
                                   : ExecuteProtection::ExecuteRead;
    } else {
        facts.execute = ExecuteProtection::NotExecutable;
    }
    return facts;
}

RegionCodeClass ClassifyRegionCode(const RegionRecord& record) noexcept {
    if (record.state != RegionState::Commit) {
        return record.state == RegionState::Unknown ? RegionCodeClass::Unknown
                                                    : RegionCodeClass::NotCommitted;
    }
    const ProtectionFacts facts = EffectiveProtection(record);
    if (facts.execute == ExecuteProtection::Unknown) {
        // 基本值看不懂，或者来源根本没填保护信息 —— 两种情况都不敢下判断。
        return RegionCodeClass::Unknown;
    }
    if (!ExecuteProtectionIsExecutable(facts.execute)) {
        return RegionCodeClass::NonExecutable;
    }
    switch (record.type) {
    case RegionType::Image: return RegionCodeClass::ImageExecutable;
    case RegionType::Private: return RegionCodeClass::PrivateExecutable;
    case RegionType::Mapped: return RegionCodeClass::MappedExecutable;
    case RegionType::Unknown: break;
    }
    return RegionCodeClass::Unknown;
}

// ---------------------------------------------------------------------------
// 地址空间索引
// ---------------------------------------------------------------------------

std::size_t AddressSpaceIndex::findEntry(const std::uint64_t va) const noexcept {
    // 只在前 searchableCount 条里二分：它们按 base 升序、区间有效且互不重叠
    // （同一次 VirtualQueryEx 遍历的性质）。尾部的残缺记录不参与查找。
    std::size_t low = 0;
    std::size_t high = std::min(searchableCount, entries.size());
    while (low < high) {
        const std::size_t mid = low + (high - low) / 2U;
        const RegionRecord& record = entries[mid];
        const std::uint64_t begin = record.base.value;
        const std::uint64_t end = begin + record.size.value;  // 溢出在 Build 阶段已剔除
        if (va < begin) {
            high = mid;
        } else if (va >= end) {
            low = mid + 1U;
        } else {
            return mid;
        }
    }
    return kNoEntry;
}

const AllocationGroup* AddressSpaceIndex::groupForEntry(
    const std::size_t entryIndex) const noexcept {
    if (entryIndex >= entryGroup.size()) {
        return nullptr;
    }
    const std::size_t groupIndex = entryGroup[entryIndex];
    if (groupIndex >= groups.size()) {
        return nullptr;
    }
    return &groups[groupIndex];
}

bool AddressSpaceIndex::usableForAbsenceInference() const noexcept {
    return OutcomeIsSuccess(outcome) && coverage.fullyCovered();
}

AddressSpaceIndex BuildAddressSpaceIndex(std::vector<RegionRecord> records,
                                         const CollectionOutcome& outcome) {
    AddressSpaceIndex index;
    index.outcome = outcome;

    // base/size 缺失或相加溢出的记录不能参与区间查找。它们仍然保留下来（证据不丢），
    // 但计入 coverage.failed —— 否则"少了几条区域"会静默消失。
    std::vector<RegionRecord> usable;
    std::vector<RegionRecord> broken;
    usable.reserve(records.size());
    for (RegionRecord& record : records) {
        const bool hasRange = record.base.present && record.size.present &&
                              record.size.value != 0U &&
                              record.base.value <= (UINT64_MAX - record.size.value);
        if (hasRange) {
            usable.push_back(std::move(record));
        } else {
            broken.push_back(std::move(record));
        }
    }

    std::sort(usable.begin(), usable.end(),
              [](const RegionRecord& a, const RegionRecord& b) {
                  return a.base.value < b.base.value;
              });

    index.entries = std::move(usable);
    const std::size_t usableCount = index.entries.size();
    index.searchableCount = usableCount;
    for (RegionRecord& record : broken) {
        index.entries.push_back(std::move(record));
    }

    index.codeClasses.reserve(index.entries.size());
    index.entryGroup.reserve(index.entries.size());
    std::unordered_map<std::uint64_t, std::size_t> groupByKey;
    std::uint64_t requestedBegin = 0;
    std::uint64_t requestedEnd = 0;
    bool haveRange = false;

    for (std::size_t i = 0; i < index.entries.size(); ++i) {
        const RegionRecord& record = index.entries[i];
        const RegionCodeClass codeClass = ClassifyRegionCode(record);
        index.codeClasses.push_back(codeClass);

        const bool inRange = i < usableCount;
        if (inRange) {
            const std::uint64_t begin = record.base.value;
            const std::uint64_t end = begin + record.size.value;
            if (!haveRange) {
                requestedBegin = begin;
                requestedEnd = end;
                haveRange = true;
            } else {
                requestedBegin = std::min(requestedBegin, begin);
                requestedEnd = std::max(requestedEnd, end);
            }
        }

        const ProtectionFacts facts = EffectiveProtection(record);
        const bool executable = IsDynamicCodeCandidate(codeClass) ||
                                codeClass == RegionCodeClass::ImageExecutable;
        const std::uint64_t size = record.size.present ? record.size.value : 0U;
        if (record.state == RegionState::Commit) {
            index.committedBytes += size;
        }
        if (executable) {
            index.executableBytes += size;
        }
        if (IsDynamicCodeCandidate(codeClass)) {
            ++index.dynamicCodeCandidateCount;
        }

        // 聚合键：有 AllocationBase 就用它，没有就用自己的 base 单独成组。
        // 不允许把"没有 AllocationBase"的区域并进别人的组 —— 那是编造归属。
        const std::uint64_t key = record.allocationBase.present
                                      ? record.allocationBase.value
                                      : (record.base.present ? record.base.value : i);
        auto it = groupByKey.find(key);
        if (it == groupByKey.end()) {
            AllocationGroup group;
            group.allocationBase = record.allocationBase;
            group.type = record.type;
            group.mappedPath = record.mappedPath;
            groupByKey.emplace(key, index.groups.size());
            index.groups.push_back(std::move(group));
            it = groupByKey.find(key);
        }
        index.entryGroup.push_back(it->second);
        AllocationGroup& group = index.groups[it->second];
        group.entryIndices.push_back(i);
        if (group.type != record.type) {
            group.typeMixed = true;
            group.type = RegionType::Unknown;
        }
        if (group.mappedPath != record.mappedPath) {
            group.mappedPathMixed = true;
            group.mappedPath.clear();
        }
        if (record.state == RegionState::Commit) {
            group.committedBytes += size;
        }
        if (executable) {
            group.executableBytes += size;
            group.anyExecutable = true;
            if (facts.writable) {
                group.anyWritableExecutable = true;
            }
        }
        if (facts.guard) {
            group.anyGuard = true;
        }
        if (codeClass == RegionCodeClass::Unknown && record.state == RegionState::Commit) {
            group.anyProtectionUnknown = true;
        }
    }

    index.coverage.succeeded = usableCount;
    index.coverage.failed = index.entries.size() - usableCount;
    index.coverage.totalKnown = OptionalU64::of(index.entries.size());
    if (haveRange) {
        index.coverage.requestedBegin = OptionalU64::of(requestedBegin);
        index.coverage.requestedEnd = OptionalU64::of(requestedEnd);
        index.coverage.processedBegin = OptionalU64::of(requestedBegin);
        index.coverage.processedEnd = OptionalU64::of(requestedEnd);
    }
    return index;
}

// ---------------------------------------------------------------------------
// 进程列表用的廉价筛选汇总
// ---------------------------------------------------------------------------

const char* SurfaceScreenStateName(const SurfaceScreenState state) noexcept {
    switch (state) {
    case SurfaceScreenState::NotScreened: return "NotScreened";
    case SurfaceScreenState::AccessDenied: return "AccessDenied";
    case SurfaceScreenState::IdentityMismatch: return "IdentityMismatch";
    case SurfaceScreenState::Failed: return "Failed";
    case SurfaceScreenState::Screened: return "Screened";
    }
    return "NotScreened";
}

bool SurfaceScreenCountsAreMeaningful(const SurfaceScreenState state) noexcept {
    return state == SurfaceScreenState::Screened;
}

ProcessSurfaceScreen SummarizeSurfaceScreen(const AddressSpaceIndex& index,
                                            const OptionalU64& screenedUtc100ns) {
    ProcessSurfaceScreen screen;
    screen.screenedUtc100ns = screenedUtc100ns;

    switch (index.outcome.status) {
    case CollectionStatus::AccessDenied:
        screen.state = SurfaceScreenState::AccessDenied;
        return screen;   // 计数保持 0，但状态说明这 0 是"不知道"
    case CollectionStatus::NotCollected:
        screen.state = SurfaceScreenState::NotScreened;
        return screen;
    case CollectionStatus::Unsupported:
    case CollectionStatus::Timeout:
    case CollectionStatus::Error:
        screen.state = SurfaceScreenState::Failed;
        return screen;
    case CollectionStatus::Success:
    case CollectionStatus::Partial:
        break;
    }

    screen.state = SurfaceScreenState::Screened;
    screen.regionCount = static_cast<std::uint32_t>(index.entries.size());
    for (std::size_t i = 0; i < index.entries.size() && i < index.codeClasses.size(); ++i) {
        if (!IsDynamicCodeCandidate(index.codeClasses[i])) {
            continue;
        }
        ++screen.dynamicCodeRegions;
        const RegionRecord& record = index.entries[i];
        screen.dynamicCodeBytes += record.size.valueOr(0U);
        if (EffectiveProtection(record).writable) {
            ++screen.writableExecutableRegions;
        }
    }
    return screen;
}

// ---------------------------------------------------------------------------
// 模块交叉视图
// ---------------------------------------------------------------------------

const char* ModuleCrossIssueName(const ModuleCrossIssue issue) noexcept {
    switch (issue) {
    case ModuleCrossIssue::ImageMappingWithoutLoaderEntry: return "ImageMappingWithoutLoaderEntry";
    case ModuleCrossIssue::LoaderEntryWithoutImageMapping: return "LoaderEntryWithoutImageMapping";
    case ModuleCrossIssue::LoaderPathMismatch: return "LoaderPathMismatch";
    case ModuleCrossIssue::LoaderSizeMismatch: return "LoaderSizeMismatch";
    case ModuleCrossIssue::MainImageIdentityConflict: return "MainImageIdentityConflict";
    case ModuleCrossIssue::MappedPathUnavailable: return "MappedPathUnavailable";
    }
    return "MappedPathUnavailable";
}

bool ModuleCrossIssueIsContradiction(const ModuleCrossIssue issue) noexcept {
    switch (issue) {
    case ModuleCrossIssue::LoaderPathMismatch:
    case ModuleCrossIssue::LoaderSizeMismatch:
    case ModuleCrossIssue::MainImageIdentityConflict:
        return true;
    case ModuleCrossIssue::ImageMappingWithoutLoaderEntry:
    case ModuleCrossIssue::LoaderEntryWithoutImageMapping:
    case ModuleCrossIssue::MappedPathUnavailable:
        return false;
    }
    return false;
}

const char* PayloadStructureName(const PayloadStructure structure) noexcept {
    switch (structure) {
    case PayloadStructure::NotExamined: return "NotExamined";
    case PayloadStructure::Unreadable: return "Unreadable";
    case PayloadStructure::NoStructure: return "NoStructure";
    case PayloadStructure::DataOnlyPeFile: return "DataOnlyPeFile";
    case PayloadStructure::MappedPeImage: return "MappedPeImage";
    case PayloadStructure::HeaderErasedPe: return "HeaderErasedPe";
    case PayloadStructure::BareCode: return "BareCode";
    }
    return "NotExamined";
}

ModuleCrossViewReport EvaluateModuleCrossView(const ModuleCrossViewInput& input) {
    ModuleCrossViewReport report;
    report.payloadCandidates = input.payloadView.size();

    const bool loaderUsable = OutcomeIsSuccess(input.loaderOutcome);
    const bool imageUsable = OutcomeIsSuccess(input.imageOutcome);
    // X-06 同款规则：只有两侧都成功才允许说"这边有那边没有"。
    // WOW64 采集器的列表天然不完整，所以它也不够资格做缺项推断。
    report.absenceInferenceAllowed =
        loaderUsable && imageUsable &&
        input.loaderTrust != ModuleEnumerationTrust::FilterIgnoredUnderWow64;

    if (!loaderUsable) {
        AddUnique(report.coverageGapKeys, kGapLoaderViewUnavailable);
    }
    if (!imageUsable) {
        AddUnique(report.coverageGapKeys, kGapImageViewUnavailable);
    }
    if (!OutcomeIsSuccess(input.payloadOutcome)) {
        AddUnique(report.coverageGapKeys, kGapPayloadViewUnavailable);
    }
    if (input.loaderTrust == ModuleEnumerationTrust::FilterIgnoredUnderWow64) {
        AddUnique(report.coverageGapKeys, kGapModuleEnumerationWow64);
    }

    // 映射视图按基址建索引。
    std::unordered_map<std::uint64_t, std::size_t> mappingByBase;
    for (std::size_t i = 0; i < input.imageView.size(); ++i) {
        const ImageMappingEntry& entry = input.imageView[i];
        if (entry.allocationBase.present) {
            mappingByBase.emplace(entry.allocationBase.value, i);
        }
        if (!OutcomeIsSuccess(entry.pathOutcome) || entry.mappedPath.empty()) {
            // 路径查询失败必须保留原因。它是缺口，不是"无文件植入"。
            ModuleCrossFinding finding;
            finding.issue = ModuleCrossIssue::MappedPathUnavailable;
            finding.base = entry.allocationBase;
            finding.mappedSize = entry.mappedSize;
            finding.inputOutcome = entry.pathOutcome;
            AddFact(finding.facts, "mapped.path.status",
                    CollectionStatusName(entry.pathOutcome.status));
            if (!entry.pathOutcome.message.empty()) {
                AddFact(finding.facts, "mapped.path.message", entry.pathOutcome.message);
            }
            report.findings.push_back(std::move(finding));
            AddUnique(report.coverageGapKeys, kGapMappedPathUnavailable);
        }
    }

    std::vector<bool> mappingMatched(input.imageView.size(), false);

    for (const LoaderModuleEntry& loaded : input.loaderView) {
        const bool haveBase = loaded.module.imageBase.present;
        auto it = haveBase ? mappingByBase.find(loaded.module.imageBase.value)
                           : mappingByBase.end();
        if (it == mappingByBase.end()) {
            if (!report.absenceInferenceAllowed || !haveBase) {
                continue;  // 没资格推断缺项就不产出，缺口键已经记过
            }
            ++report.loaderOnly;
            ModuleCrossFinding finding;
            finding.issue = ModuleCrossIssue::LoaderEntryWithoutImageMapping;
            finding.base = loaded.module.imageBase;
            finding.loaderPath = loaded.module.imagePath;
            finding.loaderSize = loaded.module.imageSize;
            finding.inputOutcome = CollectionOutcome::success();
            AddFact(finding.facts, "loader.name", loaded.listedName);
            AddFact(finding.facts, "loader.base", HexText(loaded.module.imageBase.value));
            report.findings.push_back(std::move(finding));
            continue;
        }

        mappingMatched[it->second] = true;
        ++report.matchedModules;
        const ImageMappingEntry& mapping = input.imageView[it->second];

        if (!mapping.mappedPath.empty() && !loaded.module.imagePath.empty() &&
            !PathsCompatible(loaded.module.imagePath, mapping.mappedPath)) {
            ModuleCrossFinding finding;
            finding.issue = ModuleCrossIssue::LoaderPathMismatch;
            finding.base = loaded.module.imageBase;
            finding.loaderPath = loaded.module.imagePath;
            finding.mappedPath = mapping.mappedPath;
            finding.inputOutcome = CollectionOutcome::success();
            AddFact(finding.facts, "loader.path", loaded.module.imagePath);
            AddFact(finding.facts, "mapped.path", mapping.mappedPath);
            report.findings.push_back(std::move(finding));
        }

        if (loaded.module.imageSize.present && mapping.mappedSize.present) {
            const std::uint64_t declared = loaded.module.imageSize.value;
            const std::uint64_t mapped = mapping.mappedSize.value;
            const std::uint64_t diff = declared > mapped ? declared - mapped : mapped - declared;
            if (diff > input.sizeToleranceBytes) {
                ModuleCrossFinding finding;
                finding.issue = ModuleCrossIssue::LoaderSizeMismatch;
                finding.base = loaded.module.imageBase;
                finding.loaderPath = loaded.module.imagePath;
                finding.mappedPath = mapping.mappedPath;
                finding.loaderSize = loaded.module.imageSize;
                finding.mappedSize = mapping.mappedSize;
                finding.inputOutcome = CollectionOutcome::success();
                AddFact(finding.facts, "loader.size", HexText(declared));
                AddFact(finding.facts, "mapped.size", HexText(mapped));
                AddFact(finding.facts, "size.tolerance", HexText(input.sizeToleranceBytes));
                report.findings.push_back(std::move(finding));
            }
        }
    }

    if (report.absenceInferenceAllowed) {
        for (std::size_t i = 0; i < input.imageView.size(); ++i) {
            if (mappingMatched[i]) {
                continue;
            }
            const ImageMappingEntry& mapping = input.imageView[i];
            ++report.mappingOnly;
            ModuleCrossFinding finding;
            finding.issue = ModuleCrossIssue::ImageMappingWithoutLoaderEntry;
            finding.base = mapping.allocationBase;
            finding.mappedPath = mapping.mappedPath;
            finding.mappedSize = mapping.mappedSize;
            finding.inputOutcome = CollectionOutcome::success();
            AddFact(finding.facts, "mapped.path", mapping.mappedPath);
            if (mapping.allocationBase.present) {
                AddFact(finding.facts, "mapped.base", HexText(mapping.allocationBase.value));
            }
            report.findings.push_back(std::move(finding));
        }
    }

    // 主映像：三个来源两两核对。任何一对矛盾都记一条，缺来源只记缺口。
    {
        int available = 0;
        if (!input.mainImagePathFromLoader.empty()) { ++available; }
        if (!input.mainImagePathFromKernel.empty()) { ++available; }
        if (!input.mainImagePathFromMapping.empty()) { ++available; }
        if (available < 2) {
            AddUnique(report.coverageGapKeys, kGapMainImageSourceMissing);
        }

        std::vector<std::string> conflictFacts;
        const bool loaderVsKernel =
            !PathsCompatible(input.mainImagePathFromLoader, input.mainImagePathFromKernel);
        const bool loaderVsMapping =
            !PathsCompatible(input.mainImagePathFromLoader, input.mainImagePathFromMapping);
        const bool kernelVsMapping =
            !PathsCompatible(input.mainImagePathFromKernel, input.mainImagePathFromMapping);
        if (loaderVsKernel) {
            AddFact(conflictFacts, "main.loader-vs-kernel",
                    input.mainImagePathFromLoader + " | " + input.mainImagePathFromKernel);
        }
        if (loaderVsMapping) {
            AddFact(conflictFacts, "main.loader-vs-mapping",
                    input.mainImagePathFromLoader + " | " + input.mainImagePathFromMapping);
        }
        if (kernelVsMapping) {
            AddFact(conflictFacts, "main.kernel-vs-mapping",
                    input.mainImagePathFromKernel + " | " + input.mainImagePathFromMapping);
        }
        const bool baseConflict = input.mainImageBaseFromLoader.present &&
                                  input.mainImageBaseFromMapping.present &&
                                  input.mainImageBaseFromLoader.value !=
                                      input.mainImageBaseFromMapping.value;
        if (baseConflict) {
            AddFact(conflictFacts, "main.base.loader",
                    HexText(input.mainImageBaseFromLoader.value));
            AddFact(conflictFacts, "main.base.mapping",
                    HexText(input.mainImageBaseFromMapping.value));
        }
        if (!conflictFacts.empty()) {
            ModuleCrossFinding finding;
            finding.issue = ModuleCrossIssue::MainImageIdentityConflict;
            finding.base = input.mainImageBaseFromLoader;
            finding.loaderPath = input.mainImagePathFromLoader;
            finding.mappedPath = input.mainImagePathFromMapping;
            finding.inputOutcome = CollectionOutcome::success();
            finding.facts = std::move(conflictFacts);
            report.findings.push_back(std::move(finding));
        }
    }

    // 结论：没有可用观测就是 NoEvidence，不是"未发现差异"。
    // 注意 MappedPathUnavailable 不算"差异" —— 它是缺口。把它算进去会让
    // 一次路径查询失败被表述成"观测到模块矛盾"。
    const bool anyObservation = loaderUsable || imageUsable;
    const bool anyRealDifference =
        std::any_of(report.findings.begin(), report.findings.end(),
                    [](const ModuleCrossFinding& finding) {
                        return finding.issue != ModuleCrossIssue::MappedPathUnavailable;
                    });
    if (!anyObservation) {
        report.conclusion = AnalysisConclusion::NoEvidence;
    } else if (anyRealDifference) {
        report.conclusion = AnalysisConclusion::DifferenceObserved;
    } else if (report.absenceInferenceAllowed && report.coverageGapKeys.empty()) {
        report.conclusion = AnalysisConclusion::NoDifferenceObserved;
    } else {
        report.conclusion = AnalysisConclusion::Indeterminate;
    }
    return report;
}

// ---------------------------------------------------------------------------
// 工作集筛选
// ---------------------------------------------------------------------------

const char* PageScreenVerdictName(const PageScreenVerdict verdict) noexcept {
    switch (verdict) {
    case PageScreenVerdict::NotQueried: return "NotQueried";
    case PageScreenVerdict::InvalidNeedsRecheck: return "InvalidNeedsRecheck";
    case PageScreenVerdict::PrivatizedCandidate: return "PrivatizedCandidate";
    case PageScreenVerdict::SharedNotCleared: return "SharedNotCleared";
    }
    return "NotQueried";
}

PageScreenVerdict ScreenWorkingSetPage(const WorkingSetPageFact& fact) noexcept {
    if (!fact.queried) {
        return PageScreenVerdict::NotQueried;
    }
    if (!fact.valid) {
        // Valid 为零时不能继续按有效页结构解释其余字段 —— 包括 Shared。
        return PageScreenVerdict::InvalidNeedsRecheck;
    }
    // 这里刻意不看 shareCount：Shared 表示"是否可共享"，ShareCount == 1
    // 不能代替它。
    return fact.shared ? PageScreenVerdict::SharedNotCleared
                       : PageScreenVerdict::PrivatizedCandidate;
}

bool PageSelectedForComparison(const PageScreenVerdict verdict,
                               const SurveyMode mode) noexcept {
    switch (verdict) {
    case PageScreenVerdict::PrivatizedCandidate:
        return true;
    case PageScreenVerdict::SharedNotCleared:
    case PageScreenVerdict::InvalidNeedsRecheck:
        // 深度模式不因为"共享"或"当前无效"排除任何映像页：内存合并可以让
        // 已修改页重新呈现可共享状态。
        return mode == SurveyMode::Deep;
    case PageScreenVerdict::NotQueried:
        return false;
    }
    return false;
}

// ---------------------------------------------------------------------------
// 线程起点
// ---------------------------------------------------------------------------

bool ImageCodeExtent::containsAddress(const std::uint64_t address) const noexcept {
    return size != 0U && address >= base && (address - base) < size;
}

bool ImageCodeExtent::addressInCodeExtent(const std::uint64_t address) const noexcept {
    if (!codeExtentKnown || !containsAddress(address)) {
        return false;
    }
    const std::uint64_t rva = address - base;
    return rva >= codeBeginRva && rva < codeEndRva;
}

const char* ThreadStartLandingName(const ThreadStartLanding landing) noexcept {
    switch (landing) {
    case ThreadStartLanding::NotCollected: return "NotCollected";
    case ThreadStartLanding::OutsideIndex: return "OutsideIndex";
    case ThreadStartLanding::FreeOrReserved: return "FreeOrReserved";
    case ThreadStartLanding::NonImagePrivate: return "NonImagePrivate";
    case ThreadStartLanding::NonImageMapped: return "NonImageMapped";
    case ThreadStartLanding::ImageCodeRange: return "ImageCodeRange";
    case ThreadStartLanding::ImageOutsideCode: return "ImageOutsideCode";
    case ThreadStartLanding::ImageLayoutUnknown: return "ImageLayoutUnknown";
    }
    return "NotCollected";
}

const char* ThreadContextTrustName(const ThreadContextTrust trust) noexcept {
    switch (trust) {
    case ThreadContextTrust::NotCaptured: return "NotCaptured";
    case ThreadContextTrust::RunningThreadUntrusted: return "RunningThreadUntrusted";
    case ThreadContextTrust::WaitingThreadStable: return "WaitingThreadStable";
    case ThreadContextTrust::SuspendedOrSnapshot: return "SuspendedOrSnapshot";
    }
    return "NotCaptured";
}

ThreadContextTrust ClassifyThreadContextTrust(const bool captured,
                                              const bool suspendedOrSnapshot,
                                              const bool waitingBeforeAndAfter) noexcept {
    if (!captured) {
        return ThreadContextTrust::NotCaptured;
    }
    if (suspendedOrSnapshot) {
        return ThreadContextTrust::SuspendedOrSnapshot;
    }
    // 顺序有讲究：挂起/快照优先于"两次都在等待"。两个条件同时成立时前者更强，
    // 而且它不依赖"采集期间状态没变过"这个前提。
    return waitingBeforeAndAfter ? ThreadContextTrust::WaitingThreadStable
                                 : ThreadContextTrust::RunningThreadUntrusted;
}

bool ContextUsableAsExecutionEvidence(const ThreadContextTrust trust) noexcept {
    return trust == ThreadContextTrust::SuspendedOrSnapshot ||
           trust == ThreadContextTrust::WaitingThreadStable;
}

const char* StackEvidenceKindName(const StackEvidenceKind kind) noexcept {
    switch (kind) {
    case StackEvidenceKind::ReliableUnwoundFrame: return "ReliableUnwoundFrame";
    case StackEvidenceKind::HeuristicReturnAddressCandidate:
        return "HeuristicReturnAddressCandidate";
    case StackEvidenceKind::PlainPointerReference: return "PlainPointerReference";
    }
    return "PlainPointerReference";
}

bool StackEvidenceCountsAsExecution(const StackEvidenceKind kind) noexcept {
    return kind == StackEvidenceKind::ReliableUnwoundFrame;
}

bool PayloadCandidateCanRaiseConclusion(const PayloadCandidateEntry& candidate) noexcept {
    return candidate.executableAtScanTime;
}

std::size_t AdmitStackFrames(const ThreadStackInput& stack) noexcept {
    if (!ContextUsableAsExecutionEvidence(stack.trust)) {
        // 上下文本身不可信，从它展开出来的一切都不算数。不是"降级成启发式"，
        // 是整条链作废：起点错了，后面每一步都在错的栈上走。
        return 0U;
    }
    std::size_t admitted = 0U;
    for (const RawStackFrame& frame : stack.frames) {
        if (!frame.derivedFromUnwindData || !frame.instructionPointer.present) {
            break;
        }
        ++admitted;
        if (!frame.unwindDataAvailableAtPc) {
            // 本帧的 PC 查不到展开数据 —— 它自己仍然是可靠的（由上一帧算出来的），
            // 但**下一帧**只能靠扫栈猜。可靠前缀到此为止。
            // shellcode 帧正是走这一支：它被收进来，它下面的被切掉。
            break;
        }
    }
    return admitted;
}

namespace {

// 把一个地址解释成"落在哪"。这一函数被起点和第一跳目标共用。
// owningImage 只在落在某个已知映像里时被写入，其余情况保持 nullptr ——
// "跨模块"必须靠它判定，不能靠路径字符串：私有/匿名区域根本没有路径，
// 用路径比较会把"跳进一块匿名可执行内存"判成"没跨模块"。
ThreadStartLanding ClassifyLanding(const std::uint64_t address,
                                   const AddressSpaceIndex& index,
                                   const std::vector<ImageCodeExtent>& images,
                                   std::string& owningPath,
                                   const ImageCodeExtent*& owningImage,
                                   bool& executableKnown,
                                   bool& executable) {
    owningPath.clear();
    owningImage = nullptr;
    executableKnown = false;
    executable = false;

    const std::size_t entryIndex = index.findEntry(address);
    if (entryIndex == AddressSpaceIndex::kNoEntry) {
        return ThreadStartLanding::OutsideIndex;
    }
    const RegionRecord& record = index.entries[entryIndex];
    const ProtectionFacts facts = EffectiveProtection(record);
    if (facts.execute != ExecuteProtection::Unknown) {
        executableKnown = true;
        executable = ExecuteProtectionIsExecutable(facts.execute);
    }
    owningPath = record.mappedPath;

    if (record.state != RegionState::Commit) {
        return ThreadStartLanding::FreeOrReserved;
    }
    switch (record.type) {
    case RegionType::Image: {
        for (const ImageCodeExtent& image : images) {
            if (!image.containsAddress(address)) {
                continue;
            }
            owningImage = &image;
            if (owningPath.empty()) {
                owningPath = image.path;
            }
            if (!image.codeExtentKnown) {
                return ThreadStartLanding::ImageLayoutUnknown;
            }
            return image.addressInCodeExtent(address) ? ThreadStartLanding::ImageCodeRange
                                                      : ThreadStartLanding::ImageOutsideCode;
        }
        // 是 MEM_IMAGE，但没有任何已知模块覆盖它 —— 代码布局未知。
        return ThreadStartLanding::ImageLayoutUnknown;
    }
    case RegionType::Private:
        return ThreadStartLanding::NonImagePrivate;
    case RegionType::Mapped:
        return ThreadStartLanding::NonImageMapped;
    case RegionType::Unknown:
        break;
    }
    return ThreadStartLanding::OutsideIndex;
}

} // namespace

std::vector<ThreadStartFinding> EvaluateThreadStarts(
    const std::vector<ThreadStartInput>& threads,
    const AddressSpaceIndex& index,
    const std::vector<ImageCodeExtent>& images) {
    std::vector<ThreadStartFinding> findings;
    findings.reserve(threads.size());

    for (const ThreadStartInput& input : threads) {
        ThreadStartFinding finding;
        finding.thread = input.thread;
        finding.startAddress = input.startAddress;
        finding.outcome = input.startAddressOutcome;
        finding.entryInspected = input.entryInspected;

        if (!input.startAddress.present) {
            // 起始地址根本没采到 —— 没有观测，不是"归属不一致"。
            finding.landing = ThreadStartLanding::NotCollected;
            AddFact(finding.facts, "thread.start.status",
                    CollectionStatusName(input.startAddressOutcome.status));
            findings.push_back(std::move(finding));
            continue;
        }

        std::string owningPath;
        const ImageCodeExtent* owningImage = nullptr;
        bool executableKnown = false;
        bool executable = false;
        finding.landing = ClassifyLanding(input.startAddress.value, index, images,
                                          owningPath, owningImage, executableKnown, executable);
        finding.owningPath = owningPath;
        finding.startPageExecutableKnown = executableKnown;
        finding.startPageExecutable = executable;

        AddFact(finding.facts, "thread.start.address", HexText(input.startAddress.value));
        AddFact(finding.facts, "thread.start.landing", ThreadStartLandingName(finding.landing));
        if (executableKnown) {
            // 起点页现在不可执行是一个并列事实，**不**用来忽略这条线索。
            AddFact(finding.facts, "thread.start.page-executable-now",
                    executable ? "true" : "false");
        }

        if (input.immediateBranchTarget.present) {
            std::string branchPath;
            const ImageCodeExtent* branchImage = nullptr;
            bool branchExecKnown = false;
            bool branchExec = false;
            finding.branchTarget = input.immediateBranchTarget;
            finding.branchTargetLanding =
                ClassifyLanding(input.immediateBranchTarget.value, index, images,
                                branchPath, branchImage, branchExecKnown, branchExec);
            // "起点看起来在合法模块里，但随后转到其他区域"。只有起点确实归属某个
            // 已知映像时这个判断才有意义；此时第一跳没落回同一个映像就是离开。
            finding.branchLeavesOwningModule =
                owningImage != nullptr &&
                !owningImage->containsAddress(input.immediateBranchTarget.value);
            AddFact(finding.facts, "thread.start.branch-target",
                    HexText(input.immediateBranchTarget.value));
            AddFact(finding.facts, "thread.start.branch-landing",
                    ThreadStartLandingName(finding.branchTargetLanding));
            if (!branchPath.empty()) {
                AddFact(finding.facts, "thread.start.branch-owner", branchPath);
            }
        } else if (input.entryInspected) {
            // 检查过但没解析出跳转：是失败证据，不是"没有跳转"。
            AddFact(finding.facts, "thread.start.branch", "not-resolved");
        }

        findings.push_back(std::move(finding));
    }
    return findings;
}

// ---------------------------------------------------------------------------
// 比较计划
// ---------------------------------------------------------------------------

const char* NormalizationProfileId(const SurveyMode mode) noexcept {
    // 两种模式共用同一套归一化逻辑。这个函数接收 mode 只是为了让调用点
    // 无法"顺手"分叉 —— 返回值与 mode 无关。
    static_cast<void>(mode);
    return kNormalizationProfileId;
}

std::uint32_t NormalizationProfileVersion(const SurveyMode mode) noexcept {
    static_cast<void>(mode);
    return kNormalizationProfileVersion;
}

const char* ComparisonReasonName(const ComparisonReason reason) noexcept {
    switch (reason) {
    case ComparisonReason::MainImageEntry: return "MainImageEntry";
    case ComparisonReason::SuspiciousThreadEntry: return "SuspiciousThreadEntry";
    case ComparisonReason::WorkingSetScreenedPage: return "WorkingSetScreenedPage";
    case ComparisonReason::ControlFlowReference: return "ControlFlowReference";
    case ComparisonReason::FullExecutableCoverage: return "FullExecutableCoverage";
    }
    return "MainImageEntry";
}

namespace {

const ImageCodeExtent* FindImage(const std::vector<ImageCodeExtent>& images,
                                 const std::string& path) {
    for (const ImageCodeExtent& image : images) {
        if (PathsCompatible(image.path, path) && !image.path.empty() && !path.empty()) {
            return &image;
        }
    }
    return nullptr;
}

DriverInstanceId ModuleIdOf(const ImageCodeExtent& image) {
    DriverInstanceId id;
    id.imagePath = image.path;
    id.imageBase = OptionalU64::of(image.base);
    id.imageSize = OptionalU64::of(image.size);
    return id;
}

void PushTarget(ComparisonPlan& plan,
                const ImageCodeExtent& image,
                const RvaRange& range,
                const ComparisonReason reason) {
    if (range.empty()) {
        return;
    }
    ComparisonTarget target;
    target.module = ModuleIdOf(image);
    target.range = range;
    target.reason = reason;
    plan.targets.push_back(std::move(target));
}

RvaRange ClampToImage(const ImageCodeExtent& image, std::uint64_t rva, std::uint64_t length) {
    RvaRange range;
    if (image.size == 0U || rva >= image.size) {
        return range;
    }
    const std::uint64_t available = image.size - rva;
    const std::uint64_t clamped = std::min(length, available);
    range.rva = static_cast<std::uint32_t>(rva);
    range.length = static_cast<std::uint32_t>(std::min<std::uint64_t>(clamped, 0xFFFFFFFFULL));
    return range;
}

} // namespace

ComparisonPlan BuildComparisonPlan(const ComparisonPlanInput& input) {
    ComparisonPlan plan;
    plan.mode = input.mode;
    plan.normalizationProfileId = NormalizationProfileId(input.mode);
    plan.normalizationProfileVersion = NormalizationProfileVersion(input.mode);

    const std::uint32_t window = input.entryWindowBytes == 0U ? 64U : input.entryWindowBytes;
    const std::uint32_t pageSize = input.pageSize == 0U ? 4096U : input.pageSize;

    if (input.mode == SurveyMode::Deep) {
        // 深度模式：全部应当执行的映像范围，不因为"共享"跳过。
        for (const ImageCodeExtent& image : input.images) {
            if (image.size == 0U) {
                continue;
            }
            RvaRange range;
            if (image.codeExtentKnown && image.codeEndRva > image.codeBeginRva) {
                range = ClampToImage(image, image.codeBeginRva,
                                     image.codeEndRva - image.codeBeginRva);
            } else {
                // 代码布局未知时覆盖整个映像范围，并记缺口：这是"不知道哪里是代码"，
                // 不是"没有代码"。
                range = ClampToImage(image, 0U, image.size);
                AddUnique(plan.coverageGapKeys, kGapReferenceUncertain);
            }
            PushTarget(plan, image, range, ComparisonReason::FullExecutableCoverage);
        }
    }

    // 主映像入口。
    if (!input.mainImagePath.empty()) {
        const ImageCodeExtent* image = FindImage(input.images, input.mainImagePath);
        if (image == nullptr) {
            AddUnique(plan.coverageGapKeys, kGapMainImageSourceMissing);
        } else if (!input.mainImageEntryRva.present) {
            AddUnique(plan.coverageGapKeys, kGapMainImageSourceMissing);
        } else {
            PushTarget(plan, *image,
                       ClampToImage(*image, input.mainImageEntryRva.value, window),
                       ComparisonReason::MainImageEntry);
        }
    } else {
        AddUnique(plan.coverageGapKeys, kGapMainImageSourceMissing);
    }

    for (const ComparisonPlanInput::ThreadEntrySite& site : input.threadEntrySites) {
        const ImageCodeExtent* image = FindImage(input.images, site.imagePath);
        if (image == nullptr) {
            AddUnique(plan.coverageGapKeys, kGapThreadStartUnavailable);
            continue;
        }
        PushTarget(plan, *image, ClampToImage(*image, site.rva, window),
                   ComparisonReason::SuspiciousThreadEntry);
    }

    for (const ComparisonPlanInput::ScreenedPage& page : input.screenedPages) {
        const ImageCodeExtent* image = FindImage(input.images, page.imagePath);
        if (image == nullptr) {
            AddUnique(plan.coverageGapKeys, kGapWorkingSetUnavailable);
            continue;
        }
        PushTarget(plan, *image, ClampToImage(*image, page.pageRva, pageSize),
                   ComparisonReason::WorkingSetScreenedPage);
    }

    for (const ComparisonPlanInput::ThreadEntrySite& site : input.controlFlowSites) {
        const ImageCodeExtent* image = FindImage(input.images, site.imagePath);
        if (image == nullptr) {
            continue;
        }
        PushTarget(plan, *image, ClampToImage(*image, site.rva, window),
                   ComparisonReason::ControlFlowReference);
    }

    return plan;
}

const char* ReferenceConfidenceName(const ReferenceConfidence confidence) noexcept {
    switch (confidence) {
    case ReferenceConfidence::NoReference: return "NoReference";
    case ReferenceConfidence::ReferenceUncertain: return "ReferenceUncertain";
    case ReferenceConfidence::ReferenceVerified: return "ReferenceVerified";
    }
    return "NoReference";
}

const char* ImageReferenceSourceName(const ImageReferenceSource source) noexcept {
    switch (source) {
    case ImageReferenceSource::None: return "None";
    case ImageReferenceSource::DiskFile: return "DiskFile";
    case ImageReferenceSource::SectionObject: return "SectionObject";
    }
    return "None";
}

bool SectionReferenceCoverageComplete(const ImageComparisonOutcome& outcome) noexcept {
    if (outcome.referenceSource != ImageReferenceSource::SectionObject) {
        return true;  // 别的来源不受这个账目约束
    }
    // 一页都没请求过时不能算"覆盖完整" —— 那是没比，不是比全了。
    return outcome.sectionPagesRequested != 0U &&
           outcome.sectionPagesAvailable == outcome.sectionPagesRequested;
}

bool ReferenceSupportsDifferenceClaim(const ReferenceConfidence confidence) noexcept {
    return confidence == ReferenceConfidence::ReferenceVerified;
}

// ---------------------------------------------------------------------------
// J-06：R0 扫描后端的交叉视图
// ---------------------------------------------------------------------------

const char* KernelBackendStateName(const KernelBackendState state) noexcept {
    switch (state) {
    case KernelBackendState::NotRequested: return "NotRequested";
    case KernelBackendState::DriverUnavailable: return "DriverUnavailable";
    case KernelBackendState::ProfileUnverified: return "ProfileUnverified";
    case KernelBackendState::Partial: return "Partial";
    case KernelBackendState::Available: return "Available";
    }
    return "NotRequested";
}

bool KernelBackendSupportsAbsenceInference(const KernelBackendState state) noexcept {
    return state == KernelBackendState::Available;
}

bool KernelVadView::usableForAbsenceInference() const noexcept {
    return KernelBackendSupportsAbsenceInference(state) && !truncated &&
           unreadableNodeCount == 0U && OutcomeIsSuccess(outcome);
}

const char* VadLinkIntegrityName(const VadLinkIntegrity integrity) noexcept {
    switch (integrity) {
    case VadLinkIntegrity::NotChecked: return "NotChecked";
    case VadLinkIntegrity::Consistent: return "Consistent";
    case VadLinkIntegrity::Inconsistent: return "Inconsistent";
    }
    return "NotChecked";
}

VadLinkIntegrity EvaluateVadLinkIntegrity(const KernelVadView& view) noexcept {
    // 硬闸门。遍历不完整时三项读数全部无意义 —— 返回"没查"，不是"一致"。
    if (!view.integrityValid || view.state != KernelBackendState::Available) {
        return VadLinkIntegrity::NotChecked;
    }

    // 父指针回指不上：干净的摘链不会留下这个痕迹，粗暴改写会。
    if (view.parentMismatchNodes != 0U) {
        return VadLinkIntegrity::Inconsistent;
    }
    // VadHint 指向树上找不到的节点。VadHint 为空是合法的（刚建的进程还没用过），
    // 所以只有"知道 hint 且 hint 非空"时这一条才成立。
    if (view.vadHintKnown && view.vadHintAddress.present && view.vadHintAddress.value != 0U &&
        !view.vadHintVisited) {
        return VadLinkIntegrity::Inconsistent;
    }
    // 内核计数比走出来的多：有节点不在树上。
    //
    // 只判**单向**：visitedCount < vadCount 才算。反向（走出来比计数多）在
    // 采集与内核并发改树时会自然出现（新 VAD 已挂上、计数还没加），把它也算成
    // 不一致会在忙碌进程上稳定误报。少了才是"有东西被摘走"的方向。
    if (view.vadCountKnown && view.vadCount != 0U && view.visitedCount < view.vadCount) {
        return VadLinkIntegrity::Inconsistent;
    }
    return VadLinkIntegrity::Consistent;
}

bool KernelPteView::usableForAbsenceInference() const noexcept {
    return KernelBackendSupportsAbsenceInference(state) && !truncated &&
           failedTableReads == 0U && OutcomeIsSuccess(outcome);
}

const char* KernelRegionCrossIssueName(const KernelRegionCrossIssue issue) noexcept {
    switch (issue) {
    case KernelRegionCrossIssue::VadOnlyRange: return "VadOnlyRange";
    case KernelRegionCrossIssue::R3OnlyCommittedRange: return "R3OnlyCommittedRange";
    case KernelRegionCrossIssue::ExecutableBeyondR3View: return "ExecutableBeyondR3View";
    case KernelRegionCrossIssue::ExecutableBeyondVadView: return "ExecutableBeyondVadView";
    }
    return "VadOnlyRange";
}

namespace {

// R3 索引里 [va, va+len) 是否被**已提交**区域完整覆盖。
// 注意"覆盖"必须逐页确认：VirtualQueryEx 的区域边界和 VAD 边界不一定重合，
// 只比对起点会把一段只覆盖了一半的范围判成已覆盖。
bool R3CoversCommitted(const AddressSpaceIndex& index,
                       const std::uint64_t begin,
                       const std::uint64_t end) {
    constexpr std::uint64_t kPage = 4096ULL;
    if (end <= begin) {
        return false;
    }
    for (std::uint64_t probe = begin; probe < end; probe += kPage) {
        const std::size_t entryIndex = index.findEntry(probe);
        if (entryIndex == AddressSpaceIndex::kNoEntry) {
            return false;
        }
        if (index.entries[entryIndex].state != RegionState::Commit) {
            return false;
        }
        // 一次跳到这条区域的末尾，避免对一段 64 MiB 的映射逐页问。
        const RegionRecord& record = index.entries[entryIndex];
        const std::uint64_t regionEnd = record.base.value + record.size.value;
        if (regionEnd > probe) {
            probe = (regionEnd - kPage) & ~(kPage - 1ULL);
        }
    }
    return true;
}

bool R3RangeIsExecutable(const AddressSpaceIndex& index, const std::uint64_t va) {
    const std::size_t entryIndex = index.findEntry(va);
    if (entryIndex == AddressSpaceIndex::kNoEntry ||
        entryIndex >= index.codeClasses.size()) {
        return false;
    }
    const RegionCodeClass codeClass = index.codeClasses[entryIndex];
    return codeClass == RegionCodeClass::ImageExecutable ||
           codeClass == RegionCodeClass::PrivateExecutable ||
           codeClass == RegionCodeClass::MappedExecutable;
}

bool VadCovers(const KernelVadView& view, const std::uint64_t va) {
    for (const KernelVadRegion& region : view.regions) {
        if (!region.startVa.present || !region.endVaExclusive.present) {
            continue;
        }
        if (va >= region.startVa.value && va < region.endVaExclusive.value) {
            return true;
        }
    }
    return false;
}

} // namespace

KernelCrossViewReport EvaluateKernelCrossView(const KernelCrossViewInput& input) {
    KernelCrossViewReport report;

    const bool vadRequested = input.vadView.state != KernelBackendState::NotRequested;
    const bool pteRequested = input.pteView.state != KernelBackendState::NotRequested;
    if (!vadRequested && !pteRequested) {
        // 根本没打算用内核后端：静默跳过。"没打算用"不是"想用没用上"，
        // 不该产生缺口，否则没装驱动的机器每次扫描都背一条假缺口。
        report.conclusion = AnalysisConclusion::NoEvidence;
        return report;
    }

    // 只要用了内核视图，这一条恒挂。
    AddUnique(report.capabilityLimitKeys, kLimitKernelTrustAssumption);
    AddUnique(report.capabilityLimitKeys, kLimitKernelSectionCompare);

    // 断链检查在这里定，因为这里是内核侧判据的入口。它只看树自身，和下面的
    // R3/VAD/页表交叉完全独立 —— 交叉视图全对得上时树照样可能被摘过链。
    report.linkIntegrity = EvaluateVadLinkIntegrity(input.vadView);
    report.linkVisitedCount = input.vadView.visitedCount;
    report.linkVadCount = input.vadView.vadCount;
    report.linkParentMismatchNodes = input.vadView.parentMismatchNodes;
    report.linkVadCountKnown = input.vadView.vadCountKnown;
    report.linkVadHintKnown = input.vadView.vadHintKnown;
    report.linkVadHintVisited = input.vadView.vadHintVisited;
    report.linkVadHintAddress = input.vadView.vadHintAddress;

    if (input.r3Index == nullptr) {
        AddUnique(report.coverageGapKeys, kGapAddressSpaceIncomplete);
        report.conclusion = AnalysisConclusion::NoEvidence;
        return report;
    }
    const AddressSpaceIndex& r3 = *input.r3Index;

    if (vadRequested) {
        switch (input.vadView.state) {
        case KernelBackendState::DriverUnavailable:
            AddUnique(report.coverageGapKeys, kGapKernelBackendUnavailable);
            break;
        case KernelBackendState::ProfileUnverified:
            // 偏移没为当前 build 验证过 —— 一条 finding 都不产。
            AddUnique(report.coverageGapKeys, kGapKernelProfileUnverified);
            break;
        case KernelBackendState::Partial:
            AddUnique(report.coverageGapKeys, kGapKernelBackendUnavailable);
            break;
        case KernelBackendState::Available:
        case KernelBackendState::NotRequested:
            break;
        }
        // VAD 的保护位布局没验证过，所以只比范围、不比保护。
        AddUnique(report.capabilityLimitKeys, kLimitKernelVadFlagsUnverified);
    }
    if (pteRequested) {
        switch (input.pteView.state) {
        case KernelBackendState::DriverUnavailable:
        case KernelBackendState::ProfileUnverified:
        case KernelBackendState::Partial:
            AddUnique(report.coverageGapKeys, kGapKernelBackendUnavailable);
            break;
        case KernelBackendState::Available:
        case KernelBackendState::NotRequested:
            break;
        }
    }

    const bool vadUsable = input.vadView.usableForAbsenceInference();
    const bool r3Usable = r3.usableForAbsenceInference();
    report.absenceInferenceAllowed = vadUsable && r3Usable;

    // --- VAD ↔ R3 范围交叉 ---
    if (report.absenceInferenceAllowed) {
        for (const KernelVadRegion& region : input.vadView.regions) {
            if (!region.startVa.present || !region.endVaExclusive.present ||
                region.endVaExclusive.value <= region.startVa.value) {
                continue;
            }
            if (R3CoversCommitted(r3, region.startVa.value, region.endVaExclusive.value)) {
                continue;
            }
            // VAD 说这里有一段区域，R3 的 VirtualQueryEx 没报（或报成未提交）。
            ++report.vadOnlyCount;
            KernelRegionCrossFinding finding;
            finding.issue = KernelRegionCrossIssue::VadOnlyRange;
            finding.startVa = region.startVa;
            finding.endVaExclusive = region.endVaExclusive;
            finding.inputOutcome = input.vadView.outcome;
            AddFact(finding.facts, "kernel.vad.start", HexText(region.startVa.value));
            AddFact(finding.facts, "kernel.vad.end", HexText(region.endVaExclusive.value));
            AddFact(finding.facts, "kernel.vad.private", region.privateMemory ? "true" : "false");
            AddFact(finding.facts, "kernel.vad.has-section", region.hasSection ? "true" : "false");
            if (region.vadNodeAddress.present) {
                AddFact(finding.facts, "kernel.vad.node", HexText(region.vadNodeAddress.value));
            }
            report.findings.push_back(std::move(finding));
        }

        for (std::size_t i = 0; i < r3.searchableCount && i < r3.entries.size(); ++i) {
            const RegionRecord& record = r3.entries[i];
            if (record.state != RegionState::Commit) {
                continue;
            }
            if (VadCovers(input.vadView, record.base.value)) {
                continue;
            }
            ++report.r3OnlyCount;
            KernelRegionCrossFinding finding;
            finding.issue = KernelRegionCrossIssue::R3OnlyCommittedRange;
            finding.startVa = record.base;
            finding.endVaExclusive =
                OptionalU64::of(record.base.value + record.size.value);
            finding.inputOutcome = r3.outcome;
            AddFact(finding.facts, "r3.region.start", HexText(record.base.value));
            AddFact(finding.facts, "r3.region.type", RegionTypeName(record.type));
            report.findings.push_back(std::move(finding));
        }
    }

    // --- 页表 ↔ R3/VAD ---
    // 这一侧不需要"缺项推断"资格：页表**报出来**的可执行页是正面观测，
    // 与另一侧说"这里不可执行"直接冲突，不依赖任何一方枚举完整。
    if (pteRequested && StatusCarriesObservation(input.pteView.outcome.status)) {
        for (const KernelExecutableExtent& extent : input.pteView.extents) {
            if (!extent.executable || !extent.startVa.present) {
                continue;
            }
            const std::uint64_t va = extent.startVa.value;
            const bool r3Exec = R3RangeIsExecutable(r3, va);
            const bool vadHas = vadRequested && VadCovers(input.vadView, va);

            if (!r3Exec) {
                ++report.executableBeyondViewCount;
                KernelRegionCrossFinding finding;
                finding.issue = KernelRegionCrossIssue::ExecutableBeyondR3View;
                finding.startVa = extent.startVa;
                finding.endVaExclusive = extent.byteLength.present
                    ? OptionalU64::of(va + extent.byteLength.value)
                    : OptionalU64::unset();
                finding.inputOutcome = input.pteView.outcome;
                AddFact(finding.facts, "pte.va", HexText(va));
                AddFact(finding.facts, "pte.page-size", DecText(extent.pageSize));
                AddFact(finding.facts, "pte.writable", extent.writable ? "true" : "false");
                AddFact(finding.facts, "pte.user", extent.userAccessible ? "true" : "false");
                if (vadRequested && input.vadView.usableForAbsenceInference() && !vadHas)
                    AddFact(finding.facts, "vad.covers-start", "false");
                if (extent.firstEntryValue.present) {
                    AddFact(finding.facts, "pte.value", HexText(extent.firstEntryValue.value));
                }
                report.findings.push_back(std::move(finding));
            } else if (vadRequested && input.vadView.state == KernelBackendState::Available &&
                       !vadHas) {
                ++report.executableBeyondViewCount;
                KernelRegionCrossFinding finding;
                finding.issue = KernelRegionCrossIssue::ExecutableBeyondVadView;
                finding.startVa = extent.startVa;
                finding.inputOutcome = input.pteView.outcome;
                AddFact(finding.facts, "pte.va", HexText(va));
                report.findings.push_back(std::move(finding));
            }
        }
    }

    /*
     * 结论只到 Indeterminate。理由写在这里而不是注释成"以后再说"：
     * 内核交叉差异的**合法成因目录**（写时复制、prototype PTE、共享映射的
     * 延迟建表、会话空间等）还没有在实机数据上建立过。没量过就给确定性，
     * 正是 issue 第六节点名要避免的事。等有了实机基线再考虑升档。
     */
    if (!report.findings.empty()) {
        AddUnique(report.capabilityLimitKeys, kLimitKernelBenignBaseline);
    }
    const bool anyObservation =
        (vadRequested && StatusCarriesObservation(input.vadView.outcome.status)) ||
        (pteRequested && StatusCarriesObservation(input.pteView.outcome.status));
    if (!anyObservation) {
        report.conclusion = AnalysisConclusion::NoEvidence;
    } else if (!report.findings.empty()) {
        report.conclusion = AnalysisConclusion::Indeterminate;
    } else if (report.absenceInferenceAllowed && report.coverageGapKeys.empty()) {
        report.conclusion = AnalysisConclusion::NoDifferenceObserved;
    } else {
        report.conclusion = AnalysisConclusion::Indeterminate;
    }
    return report;
}

// ---------------------------------------------------------------------------
// 例外
// ---------------------------------------------------------------------------

const char* ExceptionCategoryName(const ExceptionCategory category) noexcept {
    switch (category) {
    case ExceptionCategory::Unspecified: return "Unspecified";
    case ExceptionCategory::RuntimeDynamicCode: return "RuntimeDynamicCode";
    case ExceptionCategory::SecurityInstrumentation: return "SecurityInstrumentation";
    case ExceptionCategory::SoftwareProtection: return "SoftwareProtection";
    case ExceptionCategory::SystemCompatibility: return "SystemCompatibility";
    }
    return "Unspecified";
}

const char* ExceptionAdmissionName(const ExceptionAdmission admission) noexcept {
    switch (admission) {
    case ExceptionAdmission::Accepted: return "Accepted";
    case ExceptionAdmission::MissingRuleId: return "MissingRuleId";
    case ExceptionAdmission::MissingCategory: return "MissingCategory";
    case ExceptionAdmission::MissingTargetImageIdentity: return "MissingTargetImageIdentity";
    case ExceptionAdmission::MissingModuleIdentity: return "MissingModuleIdentity";
    case ExceptionAdmission::EmptyRange: return "EmptyRange";
    case ExceptionAdmission::RangeTooWide: return "RangeTooWide";
    }
    return "MissingRuleId";
}

ExceptionAdmission AdmitExceptionRelation(const ExceptionRelation& rule) noexcept {
    if (rule.ruleId.empty()) {
        return ExceptionAdmission::MissingRuleId;
    }
    if (rule.category == ExceptionCategory::Unspecified) {
        return ExceptionAdmission::MissingCategory;
    }
    if (rule.targetImageIdentity.empty()) {
        return ExceptionAdmission::MissingTargetImageIdentity;
    }
    if (rule.modifiedModuleIdentity.empty()) {
        return ExceptionAdmission::MissingModuleIdentity;
    }
    if (rule.modifiedRange.empty()) {
        return ExceptionAdmission::EmptyRange;
    }
    if (rule.modifiedRange.length > kExplanationRuleMaxSpanBytes) {
        // 一条覆盖整模块的"豁免"等于给整份模块永久放行。
        return ExceptionAdmission::RangeTooWide;
    }
    return ExceptionAdmission::Accepted;
}

const char* ExceptionMatchName(const ExceptionMatch match) noexcept {
    switch (match) {
    case ExceptionMatch::NoRule: return "NoRule";
    case ExceptionMatch::AllRulesRejected: return "AllRulesRejected";
    case ExceptionMatch::TargetImageMismatch: return "TargetImageMismatch";
    case ExceptionMatch::ModuleMismatch: return "ModuleMismatch";
    case ExceptionMatch::RangeNotCovered: return "RangeNotCovered";
    case ExceptionMatch::BranchTargetMismatch: return "BranchTargetMismatch";
    case ExceptionMatch::BytesUnavailable: return "BytesUnavailable";
    case ExceptionMatch::BytesMismatch: return "BytesMismatch";
    case ExceptionMatch::Matched: return "Matched";
    }
    return "NoRule";
}

std::string ModuleIdentityKeyFor(const DriverInstanceId& module) {
    const std::string key = module.crossSessionKey();
    return key.empty() ? NormalizePath(module.imagePath) : key;
}

ExceptionMatchResult MatchExceptionRelation(const std::vector<ExceptionRelation>& rules,
                                            const ExceptionQuery& query) {
    ExceptionMatchResult result;
    if (rules.empty()) {
        result.match = ExceptionMatch::NoRule;
        return result;
    }

    // 失败原因按"走到多远"排序，报最靠后的那一条，便于定位规则写错在哪。
    auto rank = [](const ExceptionMatch match) -> int {
        switch (match) {
        case ExceptionMatch::AllRulesRejected: return 0;
        case ExceptionMatch::TargetImageMismatch: return 1;
        case ExceptionMatch::ModuleMismatch: return 2;
        case ExceptionMatch::RangeNotCovered: return 3;
        case ExceptionMatch::BranchTargetMismatch: return 4;
        case ExceptionMatch::BytesUnavailable: return 5;
        case ExceptionMatch::BytesMismatch: return 6;
        case ExceptionMatch::Matched: return 7;
        case ExceptionMatch::NoRule: return -1;
        }
        return -1;
    };

    ExceptionMatch best = ExceptionMatch::AllRulesRejected;
    std::string bestRuleId;
    std::uint32_t bestRuleVersion = 0;
    ExceptionCategory bestCategory = ExceptionCategory::Unspecified;

    for (const ExceptionRelation& rule : rules) {
        if (AdmitExceptionRelation(rule) != ExceptionAdmission::Accepted) {
            ++result.rejectedRuleCount;
            continue;
        }

        ExceptionMatch outcome = ExceptionMatch::Matched;
        if (rule.targetImageIdentity != query.targetImageIdentity) {
            outcome = ExceptionMatch::TargetImageMismatch;
        } else if (rule.modifiedModuleIdentity != query.modifiedModuleIdentity) {
            outcome = ExceptionMatch::ModuleMismatch;
        } else if (!rule.modifiedRange.containsRange(query.range)) {
            // 部分覆盖不算命中：否则一条覆盖一个字节的规则能解释掉整段改写。
            outcome = ExceptionMatch::RangeNotCovered;
        } else if (!rule.allowedBranchTargetModuleIdentity.empty() &&
                   rule.allowedBranchTargetModuleIdentity !=
                       query.actualBranchTargetModuleIdentity) {
            outcome = ExceptionMatch::BranchTargetMismatch;
        } else if (!rule.expectedBytes.empty()) {
            if (!query.bytesAvailable) {
                // 规则要求字节检查却读不到字节 —— 不命中。白名单必须 fail-closed。
                outcome = ExceptionMatch::BytesUnavailable;
            } else if (rule.expectedBytes != query.actualBytes) {
                outcome = ExceptionMatch::BytesMismatch;
            }
        }

        if (rank(outcome) > rank(best)) {
            best = outcome;
            bestRuleId = rule.ruleId;
            bestRuleVersion = rule.ruleVersion;
            bestCategory = rule.category;
        }
        if (outcome == ExceptionMatch::Matched) {
            break;
        }
    }

    result.match = best;
    result.ruleId = std::move(bestRuleId);
    result.ruleVersion = bestRuleVersion;
    result.category = bestCategory;
    return result;
}

// ---------------------------------------------------------------------------
// 规则 id / 缺口键 / 检查项键
// ---------------------------------------------------------------------------

const char* const kRuleIdDynamicCodeRegion = "inject.region.dynamic-code";
const char* const kRuleIdImageBytesUnexplained = "inject.image.unexplained-diff";
const char* const kRuleIdImageReferenceUncertain = "inject.image.reference-uncertain";
const char* const kRuleIdImageWithoutLoaderEntry = "inject.module.image-without-loader";
const char* const kRuleIdLoaderEntryWithoutMapping = "inject.module.loader-without-mapping";
const char* const kRuleIdModuleIdentityMismatch = "inject.module.identity-mismatch";
const char* const kRuleIdMainImageConflict = "inject.main-image.conflict";
const char* const kRuleIdThreadStartOutsideImage = "inject.thread.start-outside-image";
const char* const kRuleIdThreadStartUnknown = "inject.thread.start-unknown";
const char* const kRuleIdThreadStartTrampoline = "inject.thread.start-trampoline";
const char* const kRuleIdPayloadStructure = "inject.payload.structure";
const char* const kRuleIdKernelRegionHiddenFromR3 = "inject.kernel.region-hidden-from-r3";
const char* const kRuleIdKernelRegionMissingInVad = "inject.kernel.region-missing-in-vad";
const char* const kRuleIdKernelExecutableBeyondView = "inject.kernel.executable-beyond-view";
const char* const kRuleIdKernelVadLinkBroken = "inject.kernel.vad-link-broken";

const char* const kGapAddressSpaceIncomplete = "inject.gap.address-space";
const char* const kGapLoaderViewUnavailable = "inject.gap.loader-view";
const char* const kGapImageViewUnavailable = "inject.gap.image-view";
const char* const kGapPayloadViewUnavailable = "inject.gap.payload-view";
const char* const kGapMappedPathUnavailable = "inject.gap.mapped-path";
const char* const kGapWorkingSetUnavailable = "inject.gap.working-set";
const char* const kGapThreadStartUnavailable = "inject.gap.thread-start";
const char* const kGapReferenceUncertain = "inject.gap.reference-uncertain";
const char* const kGapBudgetTruncated = "inject.gap.budget-truncated";
const char* const kGapIdentityChanged = "inject.gap.identity-changed";
const char* const kGapIdentityUnverifiable = "inject.gap.identity-unverifiable";
const char* const kGapModuleEnumerationWow64 = "inject.gap.module-enum-wow64";
const char* const kGapMainImageSourceMissing = "inject.gap.main-image-source";
const char* const kGapKernelBackendUnavailable = "inject.gap.kernel-backend";
const char* const kGapKernelProfileUnverified = "inject.gap.kernel-profile";
const char* const kGapVadLinkUncheckable = "inject.gap.vad-link-uncheckable";
const char* const kGapSectionReferenceIncomplete = "inject.gap.section-reference";
const char* const kGapStackWalkUntrusted = "inject.gap.stack-untrusted";
const char* const kLimitNonExecutableNotScanned = "inject.limit.non-executable";
const char* const kLimitStackUnwindUnavailable = "inject.limit.stack-unwind";
const char* const kLimitPayloadHeaderErased = "inject.limit.payload-erased-header";
const char* const kLimitRuntimeAttribution = "inject.limit.runtime-attribution";
const char* const kLimitKernelTrustAssumption = "inject.limit.kernel-trust";
const char* const kLimitKernelVadFlagsUnverified = "inject.limit.kernel-vad-flags";
const char* const kLimitKernelSectionCompare = "inject.limit.kernel-section-compare";
const char* const kLimitKernelBenignBaseline = "inject.limit.kernel-benign-baseline";
const char* const kLimitKernelBackendAbsent = "inject.limit.kernel-backend-absent";

const char* const kCheckAddressSpaceIndex = "inject.check.address-space";
const char* const kCheckModuleCrossView = "inject.check.module-cross-view";
const char* const kCheckWorkingSetScreen = "inject.check.working-set";
const char* const kCheckThreadStart = "inject.check.thread-start";
const char* const kCheckNormalizedImageDiff = "inject.check.image-diff";
const char* const kCheckPayloadStructure = "inject.check.payload-structure";
const char* const kCheckNonExecutableScan = "inject.check.non-executable";
const char* const kCheckReliableStackWalk = "inject.check.stack-walk";
const char* const kCheckKernelVadCrossView = "inject.check.kernel-vad";
const char* const kCheckVadLinkIntegrity = "inject.check.vad-link";
const char* const kCheckKernelPteScan = "inject.check.kernel-pte";

const char* EvidenceConfidenceName(const EvidenceConfidence confidence) noexcept {
    switch (confidence) {
    case EvidenceConfidence::InputIncomplete: return "InputIncomplete";
    case EvidenceConfidence::SingleObservation: return "SingleObservation";
    case EvidenceConfidence::CorroboratedIndependent: return "CorroboratedIndependent";
    }
    return "InputIncomplete";
}

bool InjectionFinding::explainedByException() const noexcept {
    return exception.match == ExceptionMatch::Matched;
}

// ---------------------------------------------------------------------------
// 观测语义表
// ---------------------------------------------------------------------------

const char* ObservationClassName(const ObservationClass observation) noexcept {
    switch (observation) {
    case ObservationClass::PrivateOrMappedExecutablePresent:
        return "PrivateOrMappedExecutablePresent";
    case ObservationClass::NormalizedImageDiffers: return "NormalizedImageDiffers";
    case ObservationClass::PayloadStructureWithReliableFrame:
        return "PayloadStructureWithReliableFrame";
    case ObservationClass::MappedModuleOutsideBaseline: return "MappedModuleOutsideBaseline";
    case ObservationClass::VadTreeLinkageInconsistent: return "VadTreeLinkageInconsistent";
    case ObservationClass::ScanCompleteNoStrongEvidence: return "ScanCompleteNoStrongEvidence";
    case ObservationClass::KeyInputUnavailable: return "KeyInputUnavailable";
    }
    return "KeyInputUnavailable";
}

ObservationSemantics SemanticsFor(const ObservationClass observation) noexcept {
    ObservationSemantics semantics;
    semantics.observation = observation;
    switch (observation) {
    case ObservationClass::PrivateOrMappedExecutablePresent:
        semantics.allowedConclusionKey = "inject.semantics.dynamic-code.allowed";
        semantics.forbiddenConclusionKey = "inject.semantics.dynamic-code.forbidden";
        semantics.contribution = AnalysisConclusion::Indeterminate;
        break;
    case ObservationClass::NormalizedImageDiffers:
        semantics.allowedConclusionKey = "inject.semantics.image-diff.allowed";
        semantics.forbiddenConclusionKey = "inject.semantics.image-diff.forbidden";
        semantics.contribution = AnalysisConclusion::DifferenceObserved;
        break;
    case ObservationClass::PayloadStructureWithReliableFrame:
        semantics.allowedConclusionKey = "inject.semantics.payload-frame.allowed";
        semantics.forbiddenConclusionKey = "inject.semantics.payload-frame.forbidden";
        semantics.contribution = AnalysisConclusion::DifferenceObserved;
        break;
    case ObservationClass::MappedModuleOutsideBaseline:
        semantics.allowedConclusionKey = "inject.semantics.module-baseline.allowed";
        semantics.forbiddenConclusionKey = "inject.semantics.module-baseline.forbidden";
        semantics.contribution = AnalysisConclusion::Indeterminate;
        break;
    case ObservationClass::VadTreeLinkageInconsistent:
        semantics.allowedConclusionKey = "inject.semantics.vad-link.allowed";
        semantics.forbiddenConclusionKey = "inject.semantics.vad-link.forbidden";
        // 只到待解释。摘链没有已知的良性成因，但**这一维的误报率还没在实机上量过**，
        // 而且遍历与内核改树是并发的。先按 Indeterminate 出货、量完再考虑升档，
        // 和 kLimitKernelBenignBaseline 是同一个理由。
        semantics.contribution = AnalysisConclusion::Indeterminate;
        break;
    case ObservationClass::ScanCompleteNoStrongEvidence:
        semantics.allowedConclusionKey = "inject.semantics.no-strong-evidence.allowed";
        semantics.forbiddenConclusionKey = "inject.semantics.no-strong-evidence.forbidden";
        semantics.contribution = AnalysisConclusion::NoDifferenceObserved;
        break;
    case ObservationClass::KeyInputUnavailable:
        semantics.allowedConclusionKey = "inject.semantics.input-unavailable.allowed";
        semantics.forbiddenConclusionKey = "inject.semantics.input-unavailable.forbidden";
        semantics.contribution = AnalysisConclusion::Indeterminate;
        break;
    }
    return semantics;
}

// ---------------------------------------------------------------------------
// 身份复核
// ---------------------------------------------------------------------------

const char* IdentityRecheckVerdictName(const IdentityRecheckVerdict verdict) noexcept {
    switch (verdict) {
    case IdentityRecheckVerdict::Same: return "Same";
    case IdentityRecheckVerdict::Changed: return "Changed";
    case IdentityRecheckVerdict::Unverifiable: return "Unverifiable";
    }
    return "Unverifiable";
}

IdentityRecheckVerdict RecheckProcessIdentity(const ProcessInstanceId& before,
                                              const ProcessInstanceId& after) noexcept {
    switch (MatchProcessInstance(before, after)) {
    case MatchResult::Confirmed: return IdentityRecheckVerdict::Same;
    case MatchResult::NoMatch: return IdentityRecheckVerdict::Changed;
    case MatchResult::Candidate: return IdentityRecheckVerdict::Unverifiable;
    }
    return IdentityRecheckVerdict::Unverifiable;
}

// ---------------------------------------------------------------------------
// 总入口
// ---------------------------------------------------------------------------

bool SurveyReport::hasObservation(const ObservationClass observation) const noexcept {
    return std::find(observations.begin(), observations.end(), observation) !=
           observations.end();
}

bool SurveyReport::hasGap(const std::string& gapKey) const noexcept {
    return std::find(coverageGapKeys.begin(), coverageGapKeys.end(), gapKey) !=
           coverageGapKeys.end();
}

bool SurveyReport::hasLimit(const std::string& limitKey) const noexcept {
    return std::find(capabilityLimitKeys.begin(), capabilityLimitKeys.end(), limitKey) !=
           capabilityLimitKeys.end();
}

namespace {

void AddObservation(SurveyReport& report, const ObservationClass observation) {
    if (!report.hasObservation(observation)) {
        report.observations.push_back(observation);
    }
}

InjectionFinding MakeFinding(const SurveyInput& input, const char* ruleId) {
    InjectionFinding finding;
    finding.ruleId = ruleId;
    finding.ruleVersion = kInjectionSurveyRuleSetVersion;
    finding.detectorVersion = input.detectorVersion;
    finding.payloadProcess = input.processBefore;
    finding.firstObservedUtc100ns = input.collectedUtc100ns;
    // 注入源进程默认未知，而且本模块不提供任何把它升格的入口。
    finding.injectorAttribution = OwnerAttribution::Unknown;
    return finding;
}

} // namespace

SurveyReport RunInjectionSurvey(const SurveyInput& input) {
    SurveyReport report;
    report.mode = input.mode;
    report.detectorVersion = input.detectorVersion;
    report.process = input.processBefore;
    report.firstObservedUtc100ns = input.collectedUtc100ns;
    report.identity = RecheckProcessIdentity(input.processBefore, input.processAfter);

    // --- 身份复核。Changed 时整份证据作废：它可能属于另一个进程实例。 ---
    if (report.identity == IdentityRecheckVerdict::Changed) {
        AddUnique(report.coverageGapKeys, kGapIdentityChanged);
        AddObservation(report, ObservationClass::KeyInputUnavailable);
        report.conclusion = AnalysisConclusion::NoEvidence;
        report.scopeIntact = false;
        report.coverageComplete = false;
        report.notPerformedCheckKeys = {
            kCheckAddressSpaceIndex, kCheckModuleCrossView, kCheckWorkingSetScreen,
            kCheckThreadStart, kCheckNormalizedImageDiff, kCheckPayloadStructure,
        };
        return report;
    }
    if (report.identity == IdentityRecheckVerdict::Unverifiable) {
        AddUnique(report.coverageGapKeys, kGapIdentityUnverifiable);
    }

    const ModuleEnumerationTrust trust =
        EvaluateModuleEnumerationTrust(input.collectorArchitecture, input.targetArchitecture);
    if (trust == ModuleEnumerationTrust::FilterIgnoredUnderWow64) {
        AddUnique(report.coverageGapKeys, kGapModuleEnumerationWow64);
    }

    // --- 地址空间索引 ---
    const bool addressSpaceUsable = StatusCarriesObservation(input.addressSpace.outcome.status);
    if (addressSpaceUsable) {
        AddUnique(report.completedCheckKeys, kCheckAddressSpaceIndex);
    } else {
        AddUnique(report.notPerformedCheckKeys, kCheckAddressSpaceIndex);
    }
    if (!input.addressSpace.usableForAbsenceInference()) {
        AddUnique(report.coverageGapKeys, kGapAddressSpaceIncomplete);
    }

    // 同一块内存不要出两行。"私有可执行"和"这块内存里有载荷结构"是同一块内存的两种
    // 说法，各报一条会让一次观测在列表里变成两条证据 —— 这正是 issue 第六节点名的
    // 重复计分（这里没有分数，但列表噪声是一样的）。所以载荷结构优先并进区域那一条。
    std::unordered_map<std::uint64_t, std::size_t> dynamicFindingByBase;

    for (std::size_t i = 0; i < input.addressSpace.entries.size() &&
                            i < input.addressSpace.codeClasses.size();
         ++i) {
        const RegionCodeClass codeClass = input.addressSpace.codeClasses[i];
        if (!IsDynamicCodeCandidate(codeClass)) {
            continue;
        }
        const RegionRecord& record = input.addressSpace.entries[i];
        ++report.dynamicCodeRegionCount;
        if (record.base.present) {
            dynamicFindingByBase.emplace(record.base.value, report.findings.size());
        }

        InjectionFinding finding = MakeFinding(input, kRuleIdDynamicCodeRegion);
        finding.address = record.base;
        finding.size = record.size;
        finding.regionType = record.type;
        finding.protection = record.protection;
        finding.mappedPath = record.mappedPath;
        finding.inputOutcome = input.addressSpace.outcome;
        finding.confidence = EvidenceConfidence::SingleObservation;
        AddFact(finding.facts, "region.code-class", RegionCodeClassName(codeClass));
        const ProtectionFacts protection = ClassifyWin32Protection(record.protection.rawValue);
        AddFact(finding.facts, "region.execute", ExecuteProtectionName(protection.execute));
        if (protection.writable) {
            AddFact(finding.facts, "region.writable", "true");
        }
        if (protection.guard) {
            AddFact(finding.facts, "region.guard", "true");
        }
        if (record.allocationBase.present) {
            AddFact(finding.facts, "region.allocation-base",
                    HexText(record.allocationBase.value));
        }
        if (record.mappedPath.empty() && record.type == RegionType::Mapped) {
            AddFact(finding.facts, "region.mapped-path", "unavailable");
            AddUnique(finding.coverageGapKeys, kGapMappedPathUnavailable);
        }
        report.findings.push_back(std::move(finding));
    }
    if (report.dynamicCodeRegionCount != 0U) {
        AddObservation(report, ObservationClass::PrivateOrMappedExecutablePresent);
    }

    // --- 模块交叉视图 ---
    if (input.moduleCrossView.conclusion != AnalysisConclusion::NoEvidence) {
        AddUnique(report.completedCheckKeys, kCheckModuleCrossView);
    } else {
        AddUnique(report.notPerformedCheckKeys, kCheckModuleCrossView);
    }
    for (const std::string& gap : input.moduleCrossView.coverageGapKeys) {
        AddUnique(report.coverageGapKeys, gap);
    }
    for (const ModuleCrossFinding& crossFinding : input.moduleCrossView.findings) {
        const char* ruleId = kRuleIdModuleIdentityMismatch;
        switch (crossFinding.issue) {
        case ModuleCrossIssue::ImageMappingWithoutLoaderEntry:
            ruleId = kRuleIdImageWithoutLoaderEntry;
            break;
        case ModuleCrossIssue::LoaderEntryWithoutImageMapping:
            ruleId = kRuleIdLoaderEntryWithoutMapping;
            break;
        case ModuleCrossIssue::MainImageIdentityConflict:
            ruleId = kRuleIdMainImageConflict;
            break;
        case ModuleCrossIssue::MappedPathUnavailable:
            // 路径取不到只是缺口，不产出 finding —— 缺口键已经并进去了。
            continue;
        case ModuleCrossIssue::LoaderPathMismatch:
        case ModuleCrossIssue::LoaderSizeMismatch:
            ruleId = kRuleIdModuleIdentityMismatch;
            break;
        }
        ++report.moduleCrossIssueCount;
        if (ModuleCrossIssueIsContradiction(crossFinding.issue)) {
            ++report.moduleCrossConflictCount;
        }
        InjectionFinding finding = MakeFinding(input, ruleId);
        finding.address = crossFinding.base;
        finding.size = crossFinding.mappedSize.present ? crossFinding.mappedSize
                                                       : crossFinding.loaderSize;
        finding.regionType = RegionType::Image;
        finding.mappedPath = crossFinding.mappedPath.empty() ? crossFinding.loaderPath
                                                             : crossFinding.mappedPath;
        finding.moduleName = FileNameOf(finding.mappedPath);
        finding.facts = crossFinding.facts;
        finding.inputOutcome = crossFinding.inputOutcome;
        finding.confidence = EvidenceConfidence::CorroboratedIndependent;
        AddFact(finding.facts, "module.cross-issue", ModuleCrossIssueName(crossFinding.issue));
        report.findings.push_back(std::move(finding));
        AddObservation(report, ObservationClass::MappedModuleOutsideBaseline);
    }

    // --- 工作集筛选 ---
    if (input.workingSetQueried && StatusCarriesObservation(input.workingSetOutcome.status)) {
        AddUnique(report.completedCheckKeys, kCheckWorkingSetScreen);
        if (!OutcomeIsSuccess(input.workingSetOutcome)) {
            AddUnique(report.coverageGapKeys, kGapWorkingSetUnavailable);
        }
    } else {
        AddUnique(report.notPerformedCheckKeys, kCheckWorkingSetScreen);
        AddUnique(report.coverageGapKeys, kGapWorkingSetUnavailable);
    }

    // --- 线程起点 ---
    if (StatusCarriesObservation(input.threadEnumerationOutcome.status) &&
        !input.threadStarts.empty()) {
        AddUnique(report.completedCheckKeys, kCheckThreadStart);
    } else {
        AddUnique(report.notPerformedCheckKeys, kCheckThreadStart);
        AddUnique(report.coverageGapKeys, kGapThreadStartUnavailable);
    }
    for (const ThreadStartFinding& start : input.threadStarts) {
        const bool anomalous = start.landing == ThreadStartLanding::NonImagePrivate ||
                               start.landing == ThreadStartLanding::NonImageMapped ||
                               start.landing == ThreadStartLanding::FreeOrReserved ||
                               start.landing == ThreadStartLanding::ImageOutsideCode;
        const bool unknown = start.landing == ThreadStartLanding::NotCollected ||
                             start.landing == ThreadStartLanding::OutsideIndex ||
                             start.landing == ThreadStartLanding::ImageLayoutUnknown;
        const bool trampoline = start.branchTarget.present &&
                                start.branchLeavesOwningModule;
        if (!anomalous && !unknown && !trampoline) {
            continue;
        }

        // 起点没采到 ≠ 归属不一致：两者用不同的 ruleId，否则一条零观测的结果
        // 会把结论从 NoEvidence 抬成 Indeterminate。
        const char* ruleId = kRuleIdThreadStartOutsideImage;
        if (unknown && !anomalous) {
            ruleId = kRuleIdThreadStartUnknown;
        } else if (trampoline && !anomalous) {
            ruleId = kRuleIdThreadStartTrampoline;
        }

        InjectionFinding finding = MakeFinding(input, ruleId);
        finding.address = start.startAddress;
        finding.mappedPath = start.owningPath;
        finding.moduleName = FileNameOf(start.owningPath);
        finding.facts = start.facts;
        finding.relatedThreads.push_back(start.thread);
        finding.inputOutcome = start.outcome;
        finding.confidence = unknown ? EvidenceConfidence::InputIncomplete
                                     : EvidenceConfidence::SingleObservation;
        if (unknown) {
            AddUnique(finding.coverageGapKeys, kGapThreadStartUnavailable);
            AddUnique(report.coverageGapKeys, kGapThreadStartUnavailable);
        } else {
            ++report.threadStartAnomalyCount;
        }
        report.findings.push_back(std::move(finding));
    }

    // --- 归一化映像比较 ---
    if (!input.imageComparisons.empty()) {
        AddUnique(report.completedCheckKeys, kCheckNormalizedImageDiff);
    } else {
        AddUnique(report.notPerformedCheckKeys, kCheckNormalizedImageDiff);
    }
    if (input.plannedComparisonsNotRun != 0U) {
        AddUnique(report.coverageGapKeys, kGapBudgetTruncated);
    }

    for (const ImageComparisonOutcome& comparison : input.imageComparisons) {
        const bool referenceUsable = ReferenceSupportsDifferenceClaim(
            comparison.referenceConfidence);
        if (!referenceUsable) {
            AddUnique(report.coverageGapKeys, kGapReferenceUncertain);
        }
        if (comparison.referenceSource == ImageReferenceSource::SectionObject) {
            ++report.sectionReferenceComparisons;
            if (!SectionReferenceCoverageComplete(comparison)) {
                // 节对象参考里有页拿不到（原型 PTE 不是 valid 形态，本版本按设计
                // 不把页面调进来）。差异仍然算数，但"没发现差异"不能成立 ——
                // 没比到的页不是比过了。
                AddUnique(report.coverageGapKeys, kGapSectionReferenceIncomplete);
            }
        }
        for (const std::string& limitation : comparison.report.limitationKeys) {
            if (ImageLimitationIsScopeDefining(limitation)) {
                AddUnique(report.capabilityLimitKeys, limitation);
            } else {
                AddUnique(report.coverageGapKeys, limitation);
            }
        }

        for (const ImageDiffEntry& entry : comparison.report.entries) {
            if (entry.kind == DiffKind::MissingLiveBytes) {
                AddUnique(report.coverageGapKeys, kGapAddressSpaceIncomplete);
                continue;
            }
            if (entry.explanation == DiffExplanation::Explained) {
                continue;  // ImageDiff 自己的规则已经解释掉了
            }

            ExceptionQuery query;
            // 目标程序版本身份与被修改模块身份是两件事：前者决定"这条豁免在哪个
            // 程序上有效"，后者决定"改的是哪个模块"。目标身份没取到时留空，
            // 任何要求非空 targetImageIdentity 的规则都匹配不上（fail-closed）。
            query.targetImageIdentity = input.targetImageIdentity;
            query.modifiedModuleIdentity = ModuleIdentityKeyFor(comparison.module);
            query.range = RvaRange{ entry.rva, entry.length };
            query.bytesAvailable = !entry.liveBytes.empty();
            query.actualBytes = entry.liveBytes;
            const ExceptionMatchResult exception =
                MatchExceptionRelation(input.exceptions, query);

            InjectionFinding finding = MakeFinding(
                input, referenceUsable ? kRuleIdImageBytesUnexplained
                                       : kRuleIdImageReferenceUncertain);
            finding.address = OptionalU64::of(entry.va);
            finding.size = OptionalU64::of(entry.length);
            finding.regionType = RegionType::Image;
            finding.mappedPath = comparison.module.imagePath;
            finding.moduleName = FileNameOf(comparison.module.imagePath);
            finding.sectionName = entry.sectionName;
            finding.rva = OptionalU64::of(entry.rva);
            finding.exception = exception;
            finding.inputOutcome = comparison.report.outcome;
            finding.confidence = referenceUsable ? EvidenceConfidence::SingleObservation
                                                 : EvidenceConfidence::InputIncomplete;
            AddFact(finding.facts, "image.reference",
                    ReferenceConfidenceName(comparison.referenceConfidence));
            AddFact(finding.facts, "image.rva", HexText(entry.rva));
            AddFact(finding.facts, "image.length", DecText(entry.length));
            AddFact(finding.facts, "image.normalization", kNormalizationProfileId);
            if (entry.byteEvidenceTruncated) {
                AddFact(finding.facts, "image.byte-evidence", "truncated");
            }
            if (exception.match == ExceptionMatch::Matched) {
                ++report.exceptionExplainedCount;
                AddFact(finding.facts, "exception.rule", exception.ruleId);
                AddFact(finding.facts, "exception.category",
                        ExceptionCategoryName(exception.category));
            } else if (referenceUsable) {
                ++report.unexplainedImageDiffCount;
            }
            if (!referenceUsable) {
                AddUnique(finding.coverageGapKeys, kGapReferenceUncertain);
            }
            report.findings.push_back(std::move(finding));
        }
    }
    if (report.unexplainedImageDiffCount != 0U) {
        AddObservation(report, ObservationClass::NormalizedImageDiffers);
    }

    // --- 栈回溯：算出可靠前缀里各帧的落点 ---
    // 采集侧只交原始帧和"上一帧有没有展开数据"这两项事实，可靠性判定全在这里，
    // 因为这一层有离线测试而采集侧没有。
    struct ReliableFrameHit final {
        std::uint64_t instructionPointer = 0U;
        ThreadInstanceId thread;
        std::size_t depth = 0U;
    };
    std::vector<ReliableFrameHit> reliableFrames;
    for (const ThreadStackInput& stack : input.threadStacks) {
        ++report.stackThreadsWalked;
        const std::size_t admitted = AdmitStackFrames(stack);
        if (admitted == 0U) {
            continue;
        }
        ++report.stackThreadsTrusted;
        for (std::size_t depth = 0U; depth < admitted; ++depth) {
            const RawStackFrame& frame = stack.frames[depth];
            if (!frame.instructionPointer.present) {
                continue;
            }
            ++report.stackReliableFrameCount;
            ReliableFrameHit hit;
            hit.instructionPointer = frame.instructionPointer.value;
            hit.thread = stack.thread;
            hit.depth = depth;
            reliableFrames.push_back(std::move(hit));
        }
    }
    // 这一位由实际产出重算，不采信调用方填的值 —— 否则"能力可用"会变成一个
    // 可以被随手置真的开关，而它是抬结论的三道闸门之一。
    const bool stackWalkAvailable = report.stackThreadsTrusted != 0U;
    if (report.stackThreadsWalked != 0U && report.stackThreadsTrusted == 0U) {
        // 做了，但一个可信上下文都没拿到。是缺口，不是能力限制。
        AddUnique(report.coverageGapKeys, kGapStackWalkUntrusted);
    }

    // --- 非映像载荷结构 ---
    bool payloadExamined = false;
    for (const PayloadCandidateEntry& payload : input.payloadCandidates) {
        if (payload.structure != PayloadStructure::NotExamined) {
            payloadExamined = true;
        }
        const bool structural = payload.structure == PayloadStructure::MappedPeImage ||
                                payload.structure == PayloadStructure::HeaderErasedPe ||
                                payload.structure == PayloadStructure::BareCode ||
                                payload.structure == PayloadStructure::DataOnlyPeFile;
        if (!structural) {
            continue;
        }

        // 这块内存已经作为动态代码区域报过了：把结构事实并进那一条，不再单独成行。
        // 记下落在哪一条上，下面"可靠帧进入"要往同一条里加线程与栈深。
        std::size_t payloadFindingIndex = report.findings.size();
        const auto existing = payload.base.present
                                  ? dynamicFindingByBase.find(payload.base.value)
                                  : dynamicFindingByBase.end();
        if (existing != dynamicFindingByBase.end() && existing->second < report.findings.size()) {
            payloadFindingIndex = existing->second;
            InjectionFinding& target = report.findings[existing->second];
            AddFact(target.facts, "payload.structure", PayloadStructureName(payload.structure));
            for (const std::string& fact : payload.structureFacts) {
                target.facts.push_back(fact);
            }
        } else {
            InjectionFinding finding = MakeFinding(input, kRuleIdPayloadStructure);
            finding.address = payload.base;
            finding.size = payload.size;
            finding.regionType = payload.type;
            finding.inputOutcome = payload.outcome;
            finding.confidence = EvidenceConfidence::SingleObservation;
            AddFact(finding.facts, "payload.structure", PayloadStructureName(payload.structure));
            // 这一位决定这条能不能参与升结论，必须能在证据里回源。
            AddFact(finding.facts, "payload.executable-at-scan",
                    payload.executableAtScanTime ? "true" : "false");
            for (const std::string& fact : payload.structureFacts) {
                finding.facts.push_back(fact);
            }
            report.findings.push_back(std::move(finding));
        }

        // 可靠帧有没有落进这块内存。调用方（或测试）已经算出来的话就认，
        // 否则用上面刚算出的可靠前缀自己判一次。
        bool frameEnters = payload.reliableFrameEntersRegion;
        const ReliableFrameHit* enteringFrame = nullptr;
        if (payload.base.present && payload.size.present && payload.size.value != 0U) {
            for (const ReliableFrameHit& hit : reliableFrames) {
                // 相减而不是相加：base + size 在畸形输入下会绕回。
                if (hit.instructionPointer >= payload.base.value &&
                    hit.instructionPointer - payload.base.value < payload.size.value) {
                    frameEnters = true;
                    enteringFrame = &hit;
                    break;
                }
            }
        }

        // "自洽载荷结构 + 可靠栈帧进入其中"才是那条更强的观测。三个条件缺一不可：
        // 栈回溯能力可用、这块内存**确实**被可靠帧进入、结构不是"数据里的一个 PE 文件"
        // （缓冲区里躺着一个 PE，与这个 PE 已经被加载执行，是两件事）。
        if (stackWalkAvailable && frameEnters &&
            PayloadCandidateCanRaiseConclusion(payload) &&
            payload.structure != PayloadStructure::DataOnlyPeFile) {
            AddObservation(report, ObservationClass::PayloadStructureWithReliableFrame);
            ++report.payloadWithExecutionCount;
            if (enteringFrame != nullptr && payloadFindingIndex < report.findings.size()) {
                // 落点要能回源到具体线程和栈深度，否则"有可靠帧进入"没法复核。
                InjectionFinding& target = report.findings[payloadFindingIndex];
                AddFact(target.facts, "stack.frame.pc", HexText(enteringFrame->instructionPointer));
                AddFact(target.facts, "stack.frame.depth", DecText(enteringFrame->depth));
                AddFact(target.facts, "stack.frame.tid",
                        DecText(enteringFrame->thread.tid.valueOr(0U)));
                target.relatedThreads.push_back(enteringFrame->thread);
                // 内存结构与线程执行是两个独立来源，凑到一起才够 CorroboratedIndependent。
                target.confidence = EvidenceConfidence::CorroboratedIndependent;
            }
        }
    }
    if (payloadExamined) {
        AddUnique(report.completedCheckKeys, kCheckPayloadStructure);
    } else {
        AddUnique(report.notPerformedCheckKeys, kCheckPayloadStructure);
    }

    // --- R0 扫描后端的交叉视图 ---
    if (input.kernelVadState != KernelBackendState::NotRequested ||
        input.kernelPteState != KernelBackendState::NotRequested) {
        if (input.kernelVadState != KernelBackendState::NotRequested) {
            if (input.kernelVadState == KernelBackendState::Available) {
                AddUnique(report.completedCheckKeys, kCheckKernelVadCrossView);
            } else {
                AddUnique(report.notPerformedCheckKeys, kCheckKernelVadCrossView);
            }
        }
        if (input.kernelPteState != KernelBackendState::NotRequested) {
            if (input.kernelPteState == KernelBackendState::Available) {
                AddUnique(report.completedCheckKeys, kCheckKernelPteScan);
            } else {
                AddUnique(report.notPerformedCheckKeys, kCheckKernelPteScan);
            }
        }
        for (const std::string& gap : input.kernelCrossView.coverageGapKeys) {
            AddUnique(report.coverageGapKeys, gap);
        }
        for (const std::string& limit : input.kernelCrossView.capabilityLimitKeys) {
            AddUnique(report.capabilityLimitKeys, limit);
        }
        for (const KernelRegionCrossFinding& crossFinding : input.kernelCrossView.findings) {
            const char* ruleId = kRuleIdKernelExecutableBeyondView;
            switch (crossFinding.issue) {
            case KernelRegionCrossIssue::VadOnlyRange:
                ruleId = kRuleIdKernelRegionHiddenFromR3;
                break;
            case KernelRegionCrossIssue::R3OnlyCommittedRange:
                ruleId = kRuleIdKernelRegionMissingInVad;
                break;
            case KernelRegionCrossIssue::ExecutableBeyondR3View:
            case KernelRegionCrossIssue::ExecutableBeyondVadView:
                ruleId = kRuleIdKernelExecutableBeyondView;
                break;
            }
            ++report.kernelCrossIssueCount;
            InjectionFinding finding = MakeFinding(input, ruleId);
            finding.address = crossFinding.startVa;
            if (crossFinding.startVa.present && crossFinding.endVaExclusive.present &&
                crossFinding.endVaExclusive.value > crossFinding.startVa.value) {
                finding.size = OptionalU64::of(
                    crossFinding.endVaExclusive.value - crossFinding.startVa.value);
            }
            finding.facts = crossFinding.facts;
            finding.inputOutcome = crossFinding.inputOutcome;
            // 两个独立来源都到场了，所以这一档是互证；但结论仍只到待解释 ——
            // 合法成因目录还没在实机上建起来（kLimitKernelBenignBaseline）。
            finding.confidence = EvidenceConfidence::CorroboratedIndependent;
            AddFact(finding.facts, "kernel.cross-issue",
                    KernelRegionCrossIssueName(crossFinding.issue));
            report.findings.push_back(std::move(finding));
        }

        // --- VAD 断链：树自身的链接自洽性 ---
        // 和上面的交叉视图是互补的两维：那一维问"两个视图说的一不一样"，
        // 这一维问"这棵树自己站不站得住"。摘链的直接痕迹在后者。
        const KernelCrossViewReport& kernel = input.kernelCrossView;
        report.vadLinkIntegrity = kernel.linkIntegrity;
        if (kernel.linkIntegrity == VadLinkIntegrity::Consistent) {
            AddUnique(report.completedCheckKeys, kCheckVadLinkIntegrity);
        } else if (kernel.linkIntegrity == VadLinkIntegrity::NotChecked) {
            // 遍历不完整（截断 / 续扫 / 有节点读不到），或者根本没跑 VAD 后端。
            // 这是**缺口**：打算查、没查成。折成"一致"就是把没查成读作树是好的。
            AddUnique(report.notPerformedCheckKeys, kCheckVadLinkIntegrity);
            if (input.kernelVadState == KernelBackendState::Available) {
                AddUnique(report.coverageGapKeys, kGapVadLinkUncheckable);
            }
        } else {
            AddUnique(report.completedCheckKeys, kCheckVadLinkIntegrity);
            ++report.vadLinkIssueCount;
            InjectionFinding finding = MakeFinding(input, kRuleIdKernelVadLinkBroken);
            // 只到"单一观测"：这一维的误报率还没在实机上量过。量完再考虑升档，
            // 和 kLimitKernelBenignBaseline 是同一个理由。
            finding.confidence = EvidenceConfidence::SingleObservation;
            AddFact(finding.facts, "vad.visited", DecText(kernel.linkVisitedCount));
            if (kernel.linkVadCountKnown) {
                AddFact(finding.facts, "vad.count-from-eprocess", DecText(kernel.linkVadCount));
            }
            AddFact(finding.facts, "vad.parent-mismatch",
                    DecText(kernel.linkParentMismatchNodes));
            if (kernel.linkVadHintKnown) {
                AddFact(finding.facts, "vad.hint",
                        HexText(kernel.linkVadHintAddress.valueOr(0U)));
                AddFact(finding.facts, "vad.hint-visited",
                        kernel.linkVadHintVisited ? "true" : "false");
            }
            AddObservation(report, ObservationClass::VadTreeLinkageInconsistent);
            report.findings.push_back(std::move(finding));
        }
    } else {
        AddUnique(report.notPerformedCheckKeys, kCheckKernelVadCrossView);
        AddUnique(report.notPerformedCheckKeys, kCheckKernelPteScan);
        AddUnique(report.notPerformedCheckKeys, kCheckVadLinkIntegrity);
    }

    // --- 深度模式的两项额外要求 ---
    if (input.mode == SurveyMode::Deep) {
        if (stackWalkAvailable) {
            AddUnique(report.completedCheckKeys, kCheckReliableStackWalk);
        } else if (report.stackThreadsWalked != 0U) {
            // 做了但没拿到可信上下文：缺口已经在上面记过，这里只记"没做成"，
            // **不**再记能力限制 —— 那会把"这次没查成"说成"本版本不做"。
            AddUnique(report.notPerformedCheckKeys, kCheckReliableStackWalk);
        } else {
            AddUnique(report.notPerformedCheckKeys, kCheckReliableStackWalk);
            AddUnique(report.capabilityLimitKeys, kLimitStackUnwindUnavailable);
        }
        if (input.nonExecutableMemoryScanned) {
            AddUnique(report.completedCheckKeys, kCheckNonExecutableScan);
        } else {
            // 载荷休眠时可以不保持执行权限，所以"只看可执行页"必须显式写出来。
            AddUnique(report.notPerformedCheckKeys, kCheckNonExecutableScan);
            AddUnique(report.capabilityLimitKeys, kLimitNonExecutableNotScanned);
        }
    } else {
        AddUnique(report.notPerformedCheckKeys, kCheckNonExecutableScan);
        AddUnique(report.notPerformedCheckKeys, kCheckReliableStackWalk);
        AddUnique(report.capabilityLimitKeys, kLimitNonExecutableNotScanned);
        AddUnique(report.capabilityLimitKeys, kLimitStackUnwindUnavailable);
    }

    // --- 采集器自报的缺口与能力限制 ---
    for (const std::string& gap : input.extraCoverageGapKeys) {
        AddUnique(report.coverageGapKeys, gap);
    }
    for (const std::string& limit : input.extraCapabilityLimitKeys) {
        AddUnique(report.capabilityLimitKeys, limit);
    }

    // --- 预算截断：截断必须显示，绝不返回"干净" ---
    if (input.budgetStop != BudgetStop::Continue) {
        AddUnique(report.coverageGapKeys, kGapBudgetTruncated);
        report.coverage.limitHit = input.budgetStop != BudgetStop::Cancelled;
        report.coverage.cancelled = input.budgetStop == BudgetStop::Cancelled;
    }

    // --- 账目 ---
    report.coverage.succeeded = report.completedCheckKeys.size();
    report.coverage.skipped = report.notPerformedCheckKeys.size();
    report.coverage.totalKnown =
        OptionalU64::of(report.completedCheckKeys.size() + report.notPerformedCheckKeys.size());
    if (!report.coverageGapKeys.empty()) {
        report.coverage.countsIncomplete = true;
    }

    report.scopeIntact = report.coverageGapKeys.empty() &&
                         report.identity == IdentityRecheckVerdict::Same &&
                         input.budgetStop == BudgetStop::Continue;
    report.coverageComplete = report.scopeIntact && report.capabilityLimitKeys.empty();
    if (!report.coverageGapKeys.empty()) {
        AddObservation(report, ObservationClass::KeyInputUnavailable);
    }

    // --- 结论 ---
    const bool anyObservation =
        addressSpaceUsable ||
        input.moduleCrossView.conclusion != AnalysisConclusion::NoEvidence ||
        !input.imageComparisons.empty() || !input.threadStarts.empty();

    if (!anyObservation) {
        report.conclusion = AnalysisConclusion::NoEvidence;
    } else if (report.unexplainedImageDiffCount != 0U ||
               report.moduleCrossConflictCount != 0U ||
               report.payloadWithExecutionCount != 0U) {
        // 只有这三类能撑起 DifferenceObserved：归一化后仍与可靠参考不同、
        // 交叉视图**矛盾**（不是"一边有一边没有"）、载荷结构且可靠帧进入其中。
        // 私有 RX 本身只是待解释的动态代码，撑不起这一档。
        report.conclusion = AnalysisConclusion::DifferenceObserved;
    } else if (report.dynamicCodeRegionCount != 0U ||
               report.threadStartAnomalyCount != 0U ||
               report.moduleCrossIssueCount != 0U ||
               report.kernelCrossIssueCount != 0U ||
               report.vadLinkIssueCount != 0U ||
               !report.coverageGapKeys.empty()) {
        report.conclusion = AnalysisConclusion::Indeterminate;
    } else {
        report.conclusion = AnalysisConclusion::NoDifferenceObserved;
        AddObservation(report, ObservationClass::ScanCompleteNoStrongEvidence);
    }

    // 硬闸门：声明要查的范围破了，就永远不可能是"未发现差异"。
    // 注意这里用的是 scopeIntact 而不是 coverageComplete —— 能力限制不该把结论
    // 永久钉死在 Indeterminate，否则四态在生产里退化成三态。
    if (!report.scopeIntact &&
        report.conclusion == AnalysisConclusion::NoDifferenceObserved) {
        report.conclusion = AnalysisConclusion::Indeterminate;
    }
    return report;
}

} // namespace Ksword::Evidence
