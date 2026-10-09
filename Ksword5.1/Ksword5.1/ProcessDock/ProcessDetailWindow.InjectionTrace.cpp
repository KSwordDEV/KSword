#include "ProcessDetailWindow.InternalCommon.h"
#include "../UI/CodeEditorWidget.h"

#include "../ksword/process/injection_trace_collector.h"

#include <QBrush>
#include <QFont>
#include <QVariant>

#include <map>

using namespace process_detail_window_internal;

namespace
{
    namespace ev = Ksword::Evidence;

    QString injectionText(const char* const key, const QString& sourceText)
    {
        static_cast<void>(key);
        return ks::i18n::sourceText(sourceText);
    }

    QString hex64(const ev::OptionalU64& value)
    {
        if (!value.present)
        {
            // 未知就是未知：绝不显示 0x0，那会被读成"地址是 0"。
            return injectionText("process.detail.injection.value.unknown",
                                 QStringLiteral("未知"));
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value.value), 0, 16)
            .toUpper()
            .replace(QStringLiteral("0X"), QStringLiteral("0x"));
    }

    QString sizeText(const ev::OptionalU64& value)
    {
        if (!value.present)
        {
            return injectionText("process.detail.injection.value.unknown",
                                 QStringLiteral("未知"));
        }
        return QStringLiteral("0x%1").arg(static_cast<qulonglong>(value.value), 0, 16).toUpper()
            .replace(QStringLiteral("0X"), QStringLiteral("0x"));
    }

    // FILETIME(100ns since 1601-01-01) -> 本地时间文本。未知就是未知，不折算成 1601。
    QString firstObservedText(const ev::OptionalU64& utc100ns)
    {
        if (!utc100ns.present)
        {
            return injectionText("process.detail.injection.value.unknown",
                                 QStringLiteral("未知"));
        }
        constexpr std::uint64_t kUnixEpochIn100ns = 116444736000000000ULL;
        if (utc100ns.value < kUnixEpochIn100ns)
        {
            return injectionText("process.detail.injection.value.unknown",
                                 QStringLiteral("未知"));
        }
        const qint64 unixMilliseconds =
            static_cast<qint64>((utc100ns.value - kUnixEpochIn100ns) / 10000ULL);
        return QDateTime::fromMSecsSinceEpoch(unixMilliseconds, QTimeZone::UTC)
            .toLocalTime()
            .toString(Qt::ISODate);
    }

    QString conclusionText(const ev::AnalysisConclusion conclusion)
    {
        switch (conclusion)
        {
        case ev::AnalysisConclusion::NoEvidence:
            return injectionText(
                "process.detail.injection.conclusion.no_evidence",
                QStringLiteral("没有可用观测（不是\"未被注入\"）"));
        case ev::AnalysisConclusion::NoDifferenceObserved:
            return injectionText(
                "process.detail.injection.conclusion.no_difference",
                QStringLiteral("已覆盖范围内未发现相应异常（不是\"从未被注入\"）"));
        case ev::AnalysisConclusion::DifferenceObserved:
            return injectionText(
                "process.detail.injection.conclusion.difference",
                QStringLiteral("观测到差异"));
        case ev::AnalysisConclusion::Indeterminate:
        default:
            return injectionText(
                "process.detail.injection.conclusion.indeterminate",
                QStringLiteral("有观测但不足以判断"));
        }
    }

    QColor conclusionColor(const ev::AnalysisConclusion conclusion)
    {
        switch (conclusion)
        {
        case ev::AnalysisConclusion::DifferenceObserved:
            return KswordTheme::ErrorColor();
        case ev::AnalysisConclusion::Indeterminate:
            return KswordTheme::WarningColor();
        case ev::AnalysisConclusion::NoDifferenceObserved:
            return KswordTheme::SuccessColor();
        case ev::AnalysisConclusion::NoEvidence:
        default:
            return KswordTheme::TextSecondaryColor();
        }
    }

    QString ruleText(const std::string& ruleId)
    {
        if (ruleId == ev::kRuleIdDynamicCodeRegion)
        {
            return injectionText("process.detail.injection.rule.dynamic_code",
                                 QStringLiteral("动态/非映像可执行内存"));
        }
        if (ruleId == ev::kRuleIdImageBytesUnexplained)
        {
            return injectionText("process.detail.injection.rule.image_diff",
                                 QStringLiteral("映像代码与可靠参考不同"));
        }
        if (ruleId == ev::kRuleIdImageReferenceUncertain)
        {
            return injectionText("process.detail.injection.rule.image_reference_uncertain",
                                 QStringLiteral("映像有差异但参考不确定"));
        }
        if (ruleId == ev::kRuleIdImageWithoutLoaderEntry)
        {
            return injectionText("process.detail.injection.rule.image_without_loader",
                                 QStringLiteral("映像映射无加载器项"));
        }
        if (ruleId == ev::kRuleIdLoaderEntryWithoutMapping)
        {
            return injectionText("process.detail.injection.rule.loader_without_mapping",
                                 QStringLiteral("加载器项无合理映射"));
        }
        if (ruleId == ev::kRuleIdModuleIdentityMismatch)
        {
            return injectionText("process.detail.injection.rule.module_identity",
                                 QStringLiteral("模块名称/大小不一致"));
        }
        if (ruleId == ev::kRuleIdMainImageConflict)
        {
            return injectionText("process.detail.injection.rule.main_image_conflict",
                                 QStringLiteral("主映像身份自相矛盾"));
        }
        if (ruleId == ev::kRuleIdThreadStartOutsideImage)
        {
            return injectionText("process.detail.injection.rule.thread_outside_image",
                                 QStringLiteral("线程起点不在模块代码内"));
        }
        if (ruleId == ev::kRuleIdThreadStartUnknown)
        {
            return injectionText("process.detail.injection.rule.thread_unknown",
                                 QStringLiteral("线程起点未采集到"));
        }
        if (ruleId == ev::kRuleIdThreadStartTrampoline)
        {
            return injectionText("process.detail.injection.rule.thread_trampoline",
                                 QStringLiteral("线程入口立即跳出本模块"));
        }
        if (ruleId == ev::kRuleIdPayloadStructure)
        {
            return injectionText("process.detail.injection.rule.payload_structure",
                                 QStringLiteral("非映像内存含载荷结构"));
        }
        if (ruleId == ev::kRuleIdKernelRegionHiddenFromR3)
        {
            return injectionText("process.detail.injection.rule.kernel_hidden",
                                 QStringLiteral("内核 VAD 有、用户态查询没有"));
        }
        if (ruleId == ev::kRuleIdKernelRegionMissingInVad)
        {
            return injectionText("process.detail.injection.rule.kernel_missing_vad",
                                 QStringLiteral("用户态有、内核 VAD 没有"));
        }
        if (ruleId == ev::kRuleIdKernelExecutableBeyondView)
        {
            return injectionText("process.detail.injection.rule.kernel_exec_beyond",
                                 QStringLiteral("页表说可执行，其它视图说不可执行"));
        }
        if (ruleId == ev::kRuleIdKernelVadLinkBroken)
        {
            return injectionText("process.detail.injection.rule.vad_link_broken",
                                 QStringLiteral("内存区域清单被人动过手脚"));
        }
        return QString::fromStdString(ruleId);
    }

    QString regionTypeText(const ev::RegionType type)
    {
        switch (type)
        {
        case ev::RegionType::Image: return QStringLiteral("IMAGE");
        case ev::RegionType::Mapped: return QStringLiteral("MAPPED");
        case ev::RegionType::Private: return QStringLiteral("PRIVATE");
        case ev::RegionType::Unknown:
        default:
            return injectionText("process.detail.injection.value.unknown",
                                 QStringLiteral("未知"));
        }
    }

    // 权限文本严格按 ExecuteProtection 四档 + 读写位拼，不再用任何位与判可执行。
    QString protectionText(const ev::RegionProtection& protection)
    {
        if (!protection.rawValue.present)
        {
            return injectionText("process.detail.injection.value.unknown",
                                 QStringLiteral("未知"));
        }
        const ev::ProtectionFacts facts = ev::ClassifyWin32Protection(protection.rawValue);
        if (facts.unrecognizedBase)
        {
            return injectionText("process.detail.injection.protect.unrecognized",
                                 QStringLiteral("无法识别(0x%1)"))
                .arg(static_cast<qulonglong>(protection.rawValue.value), 0, 16);
        }
        QString text;
        text += facts.readable ? QChar('R') : QChar('-');
        text += facts.writable ? QChar('W') : QChar('-');
        text += ev::ExecuteProtectionIsExecutable(facts.execute) ? QChar('X') : QChar('-');
        if (facts.copyOnWrite)
        {
            text += QStringLiteral("C");
        }
        if (facts.guard)
        {
            text += QStringLiteral("+GUARD");
        }
        if (facts.noAccess)
        {
            text = QStringLiteral("NOACCESS");
        }
        return text;
    }

    QString confidenceText(const ev::EvidenceConfidence confidence)
    {
        switch (confidence)
        {
        case ev::EvidenceConfidence::CorroboratedIndependent:
            return injectionText("process.detail.injection.confidence.corroborated",
                                 QStringLiteral("多来源互证"));
        case ev::EvidenceConfidence::SingleObservation:
            return injectionText("process.detail.injection.confidence.single",
                                 QStringLiteral("单一观测"));
        case ev::EvidenceConfidence::InputIncomplete:
        default:
            return injectionText("process.detail.injection.confidence.incomplete",
                                 QStringLiteral("输入不完整"));
        }
    }

    QString exceptionText(const ev::ExceptionMatchResult& exception)
    {
        if (exception.match == ev::ExceptionMatch::Matched)
        {
            return injectionText("process.detail.injection.exception.matched",
                                 QStringLiteral("已由例外解释：%1"))
                .arg(QString::fromStdString(exception.ruleId));
        }
        if (exception.match == ev::ExceptionMatch::NoRule)
        {
            return injectionText("process.detail.injection.exception.none",
                                 QStringLiteral("无例外规则"));
        }
        return injectionText("process.detail.injection.exception.unmatched",
                             QStringLiteral("未命中例外（%1）"))
            .arg(QString::fromLatin1(ev::ExceptionMatchName(exception.match)));
    }

    // 缺口键 -> 用户可读的"这一项没能查到"。默认回落到原始键，不隐藏未知项。
    QString gapText(const std::string& key)
    {
        if (key == ev::kGapAddressSpaceIncomplete)
        {
            return injectionText("process.detail.injection.gap.address_space",
                                 QStringLiteral("地址空间枚举不完整或有读不到的字节"));
        }
        if (key == ev::kGapLoaderViewUnavailable)
        {
            return injectionText("process.detail.injection.gap.loader_view",
                                 QStringLiteral("加载器模块列表不可用，缺项推断已停用"));
        }
        if (key == ev::kGapImageViewUnavailable)
        {
            return injectionText("process.detail.injection.gap.image_view",
                                 QStringLiteral("映像映射视图不完整，缺项推断已停用"));
        }
        if (key == ev::kGapPayloadViewUnavailable)
        {
            return injectionText("process.detail.injection.gap.payload_view",
                                 QStringLiteral("非映像载荷候选视图不完整"));
        }
        if (key == ev::kGapMappedPathUnavailable)
        {
            return injectionText("process.detail.injection.gap.mapped_path",
                                 QStringLiteral("部分映射来源路径查询失败（不等于\"无文件植入\"）"));
        }
        if (key == ev::kGapWorkingSetUnavailable)
        {
            return injectionText("process.detail.injection.gap.working_set",
                                 QStringLiteral("工作集页状态未能全部取得"));
        }
        if (key == ev::kGapThreadStartUnavailable)
        {
            return injectionText("process.detail.injection.gap.thread_start",
                                 QStringLiteral("部分线程起始地址未采集到"));
        }
        if (key == ev::kGapReferenceUncertain)
        {
            return injectionText("process.detail.injection.gap.reference",
                                 QStringLiteral("参考映像不确定，差异不能归为修改已证实"));
        }
        if (key == ev::kGapBudgetTruncated)
        {
            return injectionText("process.detail.injection.gap.budget",
                                 QStringLiteral("命中扫描预算，本次结果已截断"));
        }
        if (key == ev::kGapIdentityChanged)
        {
            return injectionText("process.detail.injection.gap.identity_changed",
                                 QStringLiteral("扫描期间进程身份发生变化，证据已作废"));
        }
        if (key == ev::kGapIdentityUnverifiable)
        {
            return injectionText("process.detail.injection.gap.identity_unverifiable",
                                 QStringLiteral("进程身份信息不足，无法确认前后是同一实例"));
        }
        if (key == ev::kGapModuleEnumerationWow64)
        {
            return injectionText("process.detail.injection.gap.wow64",
                                 QStringLiteral("WOW64 采集器的模块过滤参数被忽略，列表不完整"));
        }
        if (key == ev::kGapMainImageSourceMissing)
        {
            return injectionText("process.detail.injection.gap.main_image",
                                 QStringLiteral("主映像身份来源不足，无法交叉核对"));
        }
        if (key == ev::kGapVadLinkUncheckable)
        {
            return injectionText(
                "process.detail.injection.gap.vad_link",
                QStringLiteral("内存区域清单没能一次读完（条目太多被截断，或有节点读不到），所以“清单有没有被动过”这一项没查成"));
        }
        if (key == ev::kGapStackWalkUntrusted)
        {
            return injectionText(
                "process.detail.injection.gap.stack_untrusted",
                QStringLiteral("查线程调用栈时，没有一个线程是停着的——运行中的线程读到的调用栈不可信，所以这一项没查成"));
        }
        if (key == ev::kGapKernelBackendUnavailable)
        {
            return injectionText("process.detail.injection.gap.kernel_backend",
                                 QStringLiteral("内核扫描后端不可用或未走完（驱动未加载、权限不足或被截断）"));
        }
        if (key == ev::kGapKernelProfileUnverified)
        {
            return injectionText("process.detail.injection.gap.kernel_profile",
                                 QStringLiteral("当前系统版本没有经过验证的 VadRoot 偏移，内核区域视图已降级"));
        }
        return QString::fromStdString(key);
    }

    // 能力限制与覆盖缺口分开展示：前者是"本版本不做这件事"，后者是"打算查没查成"。
    QString limitText(const std::string& key)
    {
        if (key == ev::kLimitNonExecutableNotScanned)
        {
            return injectionText("process.detail.injection.limit.non_executable",
                                 QStringLiteral("未扫描非可执行内存：休眠载荷可以不保持执行权限"));
        }
        if (key == ev::kLimitStackUnwindUnavailable)
        {
            return injectionText("process.detail.injection.limit.stack_unwind",
                                 QStringLiteral("没有可靠展开的调用帧，执行关联无法建立"));
        }
        if (key == ev::kLimitPayloadHeaderErased)
        {
            return injectionText("process.detail.injection.limit.payload_erased",
                                 QStringLiteral("本版本只按残留 PE 头识别载荷，识别不了被擦除头部的载荷"));
        }
        if (key == ev::kLimitRuntimeAttribution)
        {
            return injectionText("process.detail.injection.limit.runtime",
                                 QStringLiteral("本版本不做 CLR 等运行时归因：JIT/ReadyToRun 的就地改写会表现为未解释差异"));
        }
        if (key == ev::kLimitKernelTrustAssumption)
        {
            return injectionText("process.detail.injection.limit.kernel_trust",
                                 QStringLiteral("内核采集依赖内核可信：有内核能力的对手可以改写这里读到的元数据，本功能不承诺“有驱动便无法隐藏”"));
        }
        if (key == ev::kLimitKernelVadFlagsUnverified)
        {
            return injectionText("process.detail.injection.limit.kernel_vad_flags",
                                 QStringLiteral("VAD 保护位的位布局未经版本验证，因此只比地址范围、不比保护属性"));
        }
        if (key == ev::kLimitKernelSectionCompare)
        {
            return injectionText("process.detail.injection.limit.kernel_section",
                                 QStringLiteral("本版本未做“进程映像页与 Image Section Object 参考页比较”（内核增强第三层）"));
        }
        if (key == ev::kLimitKernelBackendAbsent)
        {
            return injectionText("process.detail.injection.limit.kernel_absent",
                                 QStringLiteral("本机未加载 KswordARK 驱动，内核扫描后端本次未参与"));
        }
        if (key == ev::kLimitKernelBenignBaseline)
        {
            return injectionText("process.detail.injection.limit.kernel_baseline",
                                 QStringLiteral("内核交叉差异的合法成因目录尚未在实机数据上建立，因此这类差异一律只到“待解释”"));
        }
        return QString::fromStdString(key);
    }

    QString checkText(const std::string& key)
    {
        if (key == ev::kCheckAddressSpaceIndex)
        {
            return injectionText("process.detail.injection.check.address_space",
                                 QStringLiteral("全地址空间索引"));
        }
        if (key == ev::kCheckModuleCrossView)
        {
            return injectionText("process.detail.injection.check.module_cross_view",
                                 QStringLiteral("模块交叉视图"));
        }
        if (key == ev::kCheckWorkingSetScreen)
        {
            return injectionText("process.detail.injection.check.working_set",
                                 QStringLiteral("工作集页筛选"));
        }
        if (key == ev::kCheckThreadStart)
        {
            return injectionText("process.detail.injection.check.thread_start",
                                 QStringLiteral("线程起点及落点"));
        }
        if (key == ev::kCheckNormalizedImageDiff)
        {
            return injectionText("process.detail.injection.check.image_diff",
                                 QStringLiteral("归一化映像比较"));
        }
        if (key == ev::kCheckPayloadStructure)
        {
            return injectionText("process.detail.injection.check.payload_structure",
                                 QStringLiteral("非映像载荷结构"));
        }
        if (key == ev::kCheckNonExecutableScan)
        {
            return injectionText("process.detail.injection.check.non_executable",
                                 QStringLiteral("非可执行内存扫描"));
        }
        if (key == ev::kCheckVadLinkIntegrity)
        {
            return injectionText("process.detail.injection.check.vad_link",
                                 QStringLiteral("核对内存区域清单有没有被动过"));
        }
        if (key == ev::kCheckReliableStackWalk)
        {
            return injectionText("process.detail.injection.check.stack_walk",
                                 QStringLiteral("查线程当前的调用栈"));
        }
        if (key == ev::kCheckKernelVadCrossView)
        {
            return injectionText("process.detail.injection.check.kernel_vad",
                                 QStringLiteral("内核 VAD 交叉视图"));
        }
        if (key == ev::kCheckKernelPteScan)
        {
            return injectionText("process.detail.injection.check.kernel_pte",
                                 QStringLiteral("内核页表可执行页扫描"));
        }
        return QString::fromStdString(key);
    }

    QString observationText(const ev::ObservationClass observation)
    {
        switch (observation)
        {
        case ev::ObservationClass::PrivateOrMappedExecutablePresent:
            return injectionText(
                "process.detail.injection.observation.dynamic_code",
                QStringLiteral("存在私有/映射可执行内存 → 可以说\"存在待解释的动态代码\"，不能说\"已被恶意注入\""));
        case ev::ObservationClass::NormalizedImageDiffers:
            return injectionText(
                "process.detail.injection.observation.image_diff",
                QStringLiteral("归一化后代码仍与可靠参考不同 → 可以说\"映像代码修改已证实\"，不能说\"已确定修改者和修改目的\""));
        case ev::ObservationClass::PayloadStructureWithReliableFrame:
            return injectionText(
                "process.detail.injection.observation.payload_frame",
                QStringLiteral("非映像内存有自洽载荷结构且可靠栈帧进入其中 → 可以说\"未知内存载荷与线程执行相关联\"，不能说\"一定由远程进程注入\""));
        case ev::ObservationClass::MappedModuleOutsideBaseline:
            return injectionText(
                "process.detail.injection.observation.module_baseline",
                QStringLiteral("模块交叉视图存在矛盾 → 可以说\"存在非预期模块\"，不能说\"一定通过某种特定注入 API 进入\""));
        case ev::ObservationClass::VadTreeLinkageInconsistent:
            return injectionText(
                "process.detail.injection.observation.vad_link",
                QStringLiteral("系统记录内存区域的那棵树自己对不上 → 可以说\"有内存区域被从清单里摘掉了\"，不能说\"摘掉它的是谁、摘的是哪一块\""));
        case ev::ObservationClass::ScanCompleteNoStrongEvidence:
            return injectionText(
                "process.detail.injection.observation.no_strong_evidence",
                QStringLiteral("扫描完成但无强证据 → 只能说\"在已覆盖范围内未发现相应异常\"，不能说\"从未被注入过\""));
        case ev::ObservationClass::KeyInputUnavailable:
        default:
            return injectionText(
                "process.detail.injection.observation.input_unavailable",
                QStringLiteral("关键页面/线程/参考文件不可获得 → 只能说\"检查受限、结论不完整\"，不能说\"目标干净\""));
        }
    }

    QString failureText(const ks::process::InjectionTraceResult& result)
    {
        switch (result.status)
        {
        case ks::process::InjectionTraceStatus::ProcessIdentityUnavailable:
            return injectionText(
                "process.detail.injection.failure.identity_unavailable",
                QStringLiteral("无法确认进程实例身份（读不到创建时间），本次检查未执行。"));
        case ks::process::InjectionTraceStatus::ProcessIdentityMismatch:
            return injectionText(
                "process.detail.injection.failure.identity_mismatch",
                QStringLiteral("PID 已被复用或进程已重建，本次检查未执行。"));
        case ks::process::InjectionTraceStatus::ProcessOpenDenied:
            return injectionText(
                "process.detail.injection.failure.access_denied",
                QStringLiteral("访问受限：无法以只读权限打开目标进程（受保护进程或权限不足）。这不是\"未发现注入\"。"));
        case ks::process::InjectionTraceStatus::ProcessOpenFailed:
            return injectionText(
                "process.detail.injection.failure.open_failed",
                QStringLiteral("打开目标进程失败，本次检查未执行。"));
        case ks::process::InjectionTraceStatus::Completed:
        default:
            return QString();
        }
    }

    // 前置声明：复制出去的报告和界面上看到的必须是同一份渲染，否则两边迟早会走样。
    QString conclusionHeadline(ev::AnalysisConclusion conclusion);
    QString conclusionCaveatText(ev::AnalysisConclusion conclusion);
    QString readableFindingDetailText(const ev::InjectionFinding& finding);

    QString buildReportText(const ks::process::InjectionTraceResult& result,
                            const QString& processName)
    {
        QStringList lines;
        lines << injectionText("process.detail.injection.report.title",
                               QStringLiteral("进程注入痕迹检查报告"));
        lines << injectionText("process.detail.injection.report.target",
                               QStringLiteral("目标：%1 (PID %2)    映像：%3    架构：%4"))
                     .arg(processName)
                     .arg(result.pid)
                     .arg(result.imagePath)
                     .arg(result.architectureText);
        const QString failure = failureText(result);
        if (!failure.isEmpty())
        {
            lines << failure;
            if (!result.diagnosticText.isEmpty())
            {
                lines << injectionText("process.detail.injection.report.diagnostic",
                                       QStringLiteral("技术信息：%1"))
                             .arg(result.diagnosticText);
            }
            return lines.join(QChar('\n'));
        }

        const ev::SurveyReport& report = result.report;
        lines << injectionText("process.detail.injection.report.mode",
                               QStringLiteral("模式：%1    检测器：%2    规则集：v%3"))
                     .arg(result.requestedMode == ev::SurveyMode::Deep
                              ? injectionText("process.detail.injection.mode.deep",
                                              QStringLiteral("深度"))
                              : injectionText("process.detail.injection.mode.fast",
                                              QStringLiteral("快速")))
                     .arg(QString::fromStdString(report.detectorVersion))
                     .arg(report.ruleSetVersion);
        lines << injectionText("process.detail.injection.report.conclusion",
                               QStringLiteral("结论：%1"))
                     .arg(conclusionText(report.conclusion));
        // 结论后面紧跟大白话版本与"不能被读成什么"，和界面上第一屏保持一致。
        lines << conclusionHeadline(report.conclusion);
        lines << conclusionCaveatText(report.conclusion);
        lines << injectionText("process.detail.injection.report.counts",
                               QStringLiteral("动态代码区域 %1，模块交叉问题 %2（其中矛盾 %3），未解释映像差异 %4，线程起点异常 %5，例外解释 %6"))
                     .arg(report.dynamicCodeRegionCount)
                     .arg(report.moduleCrossIssueCount)
                     .arg(report.moduleCrossConflictCount)
                     .arg(report.unexplainedImageDiffCount)
                     .arg(report.threadStartAnomalyCount)
                     .arg(report.exceptionExplainedCount);
        lines << injectionText("process.detail.injection.report.scale",
                               QStringLiteral("区域 %1，加载器模块 %2，映像映射 %3，线程 %4，比较模块 %5（%6 段），工作集页 %7，读取 %8 字节，用时 %9 ms"))
                     .arg(result.regionCount)
                     .arg(result.loaderModuleCount)
                     .arg(result.imageMappingCount)
                     .arg(result.threadCount)
                     .arg(result.comparedModuleCount)
                     .arg(result.comparedRangeCount)
                     .arg(result.workingSetPagesQueried)
                     .arg(result.bytesRead)
                     .arg(result.elapsedMs);

        lines << injectionText("process.detail.injection.report.kernel",
                               QStringLiteral("R0 扫描后端：VAD=%1（%2 条，不可读节点 %3），页表=%4（%5 段，可执行页 %6，表读 %7），交叉差异 %8"))
                     .arg(QString::fromLatin1(
                         ev::KernelBackendStateName(result.kernelVadState)))
                     .arg(result.kernelVadRegionCount)
                     .arg(result.kernelVadUnreadableNodes)
                     .arg(QString::fromLatin1(
                         ev::KernelBackendStateName(result.kernelPteState)))
                     .arg(result.kernelExecutableExtentCount)
                     .arg(result.kernelExecutablePageCount)
                     .arg(result.kernelPteTableReads)
                     .arg(report.kernelCrossIssueCount);
        if (!result.kernelDiagnosticText.isEmpty())
        {
            lines << injectionText("process.detail.injection.report.kernel_diagnostic",
                                   QStringLiteral("R0 后端诊断：%1"))
                         .arg(result.kernelDiagnosticText);
        }

        lines << QString();
        lines << injectionText("process.detail.injection.report.observations",
                               QStringLiteral("[观测语义：能说什么 / 不能说什么]"));
        if (report.observations.empty())
        {
            lines << injectionText("process.detail.injection.report.no_observation",
                                   QStringLiteral("    （无）"));
        }
        for (const ev::ObservationClass observation : report.observations)
        {
            lines << QStringLiteral("    ") + observationText(observation);
        }

        lines << QString();
        lines << injectionText("process.detail.injection.report.completed_checks",
                               QStringLiteral("[已完成的检查]"));
        for (const std::string& key : report.completedCheckKeys)
        {
            lines << QStringLiteral("    ") + checkText(key);
        }
        lines << injectionText("process.detail.injection.report.skipped_checks",
                               QStringLiteral("[未执行的检查]"));
        for (const std::string& key : report.notPerformedCheckKeys)
        {
            lines << QStringLiteral("    ") + checkText(key);
        }
        lines << injectionText("process.detail.injection.report.gaps",
                               QStringLiteral("[检查缺口：打算查但没查成]"));
        if (report.coverageGapKeys.empty())
        {
            lines << injectionText("process.detail.injection.report.no_gap",
                                   QStringLiteral("    （无）"));
        }
        for (const std::string& key : report.coverageGapKeys)
        {
            lines << QStringLiteral("    ") + gapText(key);
        }
        lines << injectionText("process.detail.injection.report.limits",
                               QStringLiteral("[能力限制：本版本不做这件事]"));
        if (report.capabilityLimitKeys.empty())
        {
            lines << injectionText("process.detail.injection.report.no_gap",
                                   QStringLiteral("    （无）"));
        }
        for (const std::string& key : report.capabilityLimitKeys)
        {
            lines << QStringLiteral("    ") + limitText(key);
        }

        lines << QString();
        lines << injectionText("process.detail.injection.report.findings",
                               QStringLiteral("[结果条目 %1 条]"))
                     .arg(report.findings.size());
        for (const ev::InjectionFinding& finding : report.findings)
        {
            lines << QString();
            lines << readableFindingDetailText(finding);
        }
        return lines.join(QChar('\n'));
    }

    // ---------------------------------------------------------------------
    // 以下几个函数只负责"把判据层的结论翻译成一句大白话"。语义边界一个字都不能
    // 松：四态还是四态，这里做的只是把原来塞在括号里让用户自己推的限定条件，
    // 拆成独立的一句话。
    // ---------------------------------------------------------------------

    QString conclusionHeadline(const ev::AnalysisConclusion conclusion)
    {
        switch (conclusion)
        {
        case ev::AnalysisConclusion::NoEvidence:
            return injectionText("process.detail.injection.headline.no_evidence",
                                 QStringLiteral("这次没能检查成"));
        case ev::AnalysisConclusion::NoDifferenceObserved:
            return injectionText("process.detail.injection.headline.no_difference",
                                 QStringLiteral("查过的地方没发现问题"));
        case ev::AnalysisConclusion::DifferenceObserved:
            return injectionText("process.detail.injection.headline.difference",
                                 QStringLiteral("发现了对不上的地方，建议人工确认"));
        case ev::AnalysisConclusion::Indeterminate:
        default:
            return injectionText("process.detail.injection.headline.indeterminate",
                                 QStringLiteral("有现象需要人工判断，工具不替你下结论"));
        }
    }

    // 每一态"不能被读成什么"，单独一句，不再用括号夹在结论里。
    QString conclusionCaveatText(const ev::AnalysisConclusion conclusion)
    {
        switch (conclusion)
        {
        case ev::AnalysisConclusion::NoEvidence:
            return injectionText(
                "process.detail.injection.caveat.no_evidence",
                QStringLiteral("没有拿到可用的观测数据，所以既不能说有问题，也不能说没问题。原因写在「查了什么」页里。"));
        case ev::AnalysisConclusion::NoDifferenceObserved:
            return injectionText(
                "process.detail.injection.caveat.no_difference",
                QStringLiteral("这句话只对「查了什么」页里列出的范围成立，不等于这个进程从来没有被注入过。"));
        case ev::AnalysisConclusion::DifferenceObserved:
            return injectionText(
                "process.detail.injection.caveat.difference",
                QStringLiteral("发现的是「和原本该有的样子对不上」，不是「谁在什么时候注入的」——事后看内存查不出注入者是谁。"));
        case ev::AnalysisConclusion::Indeterminate:
        default:
            return injectionText(
                "process.detail.injection.caveat.indeterminate",
                QStringLiteral("看到的现象既可能来自正常功能（即时编译、加壳、杀软或输入法插桩），也可能来自注入。每一类是什么意思，下面每组标题下面都写了。"));
        }
    }

    // 分组标题下面那一行：这一类现象是什么、常见的正常成因是什么。
    // 没有这一行，用户面对"动态/非映像可执行内存 874 处"只能干瞪眼。
    QString ruleMeaningText(const std::string& ruleId)
    {
        if (ruleId == ev::kRuleIdDynamicCodeRegion)
        {
            return injectionText(
                "process.detail.injection.meaning.dynamic_code",
                QStringLiteral("不属于任何磁盘文件的可执行内存。正常来源很多：.NET / JavaScript 等即时编译、加壳程序自解压、杀软与输入法的插桩。几乎每个进程都有，数量本身不是问题，明显比同类进程多才值得看。"));
        }
        if (ruleId == ev::kRuleIdImageBytesUnexplained)
        {
            return injectionText(
                "process.detail.injection.meaning.image_diff",
                QStringLiteral("模块的代码和磁盘上的原文件不一样，并且已经排除了重定位这类系统自己做的正常改写。这是本工具能给出的最硬的一类证据。"));
        }
        if (ruleId == ev::kRuleIdImageReferenceUncertain)
        {
            return injectionText(
                "process.detail.injection.meaning.image_reference_uncertain",
                QStringLiteral("模块代码和磁盘文件对不上，但磁盘上那份文件本身没法确认是不是原版（读不到、被占用、或来源不可靠），所以这个差异暂时不能算数。"));
        }
        if (ruleId == ev::kRuleIdImageWithoutLoaderEntry)
        {
            return injectionText(
                "process.detail.injection.meaning.image_without_loader",
                QStringLiteral("内存里映射着一个 PE 映像，但系统的已加载模块清单里没登记它。资源文件和 .NET 元数据映像天然就是这样；被手工映射进来的 DLL 也是这样。"));
        }
        if (ruleId == ev::kRuleIdLoaderEntryWithoutMapping)
        {
            return injectionText(
                "process.detail.injection.meaning.loader_without_mapping",
                QStringLiteral("模块清单里登记了这个模块，内存里却找不到与之对应的映射。"));
        }
        if (ruleId == ev::kRuleIdModuleIdentityMismatch)
        {
            return injectionText(
                "process.detail.injection.meaning.module_identity",
                QStringLiteral("同一个模块，清单里写的名字或大小，和内存里实际映射的那一份对不上。"));
        }
        if (ruleId == ev::kRuleIdMainImageConflict)
        {
            return injectionText(
                "process.detail.injection.meaning.main_image_conflict",
                QStringLiteral("进程主程序自己的身份信息前后矛盾：两处来源说的不是同一个文件。"));
        }
        if (ruleId == ev::kRuleIdThreadStartOutsideImage)
        {
            return injectionText(
                "process.detail.injection.meaning.thread_outside_image",
                QStringLiteral("有线程的起始地址不落在任何模块的代码里。远程线程注入是这个样子，某些运行时自己生成的跳板也是这个样子。"));
        }
        if (ruleId == ev::kRuleIdThreadStartUnknown)
        {
            return injectionText(
                "process.detail.injection.meaning.thread_unknown",
                QStringLiteral("线程的起始地址没取到（权限不够，或线程在采集途中退出了）。这是没查成，不是查出了问题。"));
        }
        if (ruleId == ev::kRuleIdThreadStartTrampoline)
        {
            return injectionText(
                "process.detail.injection.meaning.thread_trampoline",
                QStringLiteral("线程入口的第一条指令就跳到别的模块去了，等于这个起点只是个壳，真正要跑的代码在别处。"));
        }
        if (ruleId == ev::kRuleIdPayloadStructure)
        {
            return injectionText(
                "process.detail.injection.meaning.payload_structure",
                QStringLiteral("一段不属于任何模块的内存里，出现了完整可执行文件才有的结构特征——像是有人把一个程序整个搬进了内存。如果这一条还标着「有多个独立来源互相印证」，说明有线程的调用栈确实落在这块内存里，也就是它不只是躺着，而是在被执行。"));
        }
        if (ruleId == ev::kRuleIdKernelRegionHiddenFromR3)
        {
            return injectionText(
                "process.detail.injection.meaning.kernel_hidden",
                QStringLiteral("内核的内存记录里有这块区域，从用户态查却看不到它。两个视图对不上，但正常成因的目录还没建立，所以只作为线索。"));
        }
        if (ruleId == ev::kRuleIdKernelRegionMissingInVad)
        {
            return injectionText(
                "process.detail.injection.meaning.kernel_missing_vad",
                QStringLiteral("从用户态查能看到这块内存，内核的内存记录里却没有对应条目。"));
        }
        if (ruleId == ev::kRuleIdKernelExecutableBeyondView)
        {
            return injectionText(
                "process.detail.injection.meaning.kernel_exec_beyond",
                QStringLiteral("页表说这些页可以执行，但其它视图认为它们不可执行。"));
        }
        if (ruleId == ev::kRuleIdKernelVadLinkBroken)
        {
            return injectionText(
                "process.detail.injection.meaning.vad_link_broken",
                QStringLiteral("系统内部记录内存区域用的是一棵树，这棵树自己对不上了——有节点的“父节点”不认它这个孩子，或者系统记的区域个数比树上实际找到的多。把一块内存从这棵树上摘下去，是隐藏内存最直接的做法：摘掉之后从外面就再也查询不到它，但内存本身还在、还能跑。本机 90 个进程、10199 个节点实测全部对得上，所以这一条出现即值得追查。"));
        }
        return QString();
    }

    // 一条发现在表格里显示的短描述：优先给地址，其次给模块，再不济给来源路径。
    QString findingHeadlineText(const ev::InjectionFinding& finding)
    {
        if (!finding.moduleName.empty())
        {
            return QString::fromStdString(finding.moduleName);
        }
        if (!finding.mappedPath.empty())
        {
            return QFileInfo(QString::fromStdString(finding.mappedPath)).fileName();
        }
        if (!finding.relatedThreads.empty())
        {
            return injectionText("process.detail.injection.finding.thread",
                                 QStringLiteral("线程 %1"))
                .arg(finding.relatedThreads.front().tid.valueOr(0U));
        }
        return injectionText("process.detail.injection.finding.anonymous_region",
                             QStringLiteral("匿名内存区域"));
    }

    // 大小按人读的单位给。原来一律 0x1000 十六进制，得先心算才知道是 4 KB。
    QString humanSizeText(const ev::OptionalU64& value)
    {
        if (!value.present)
        {
            return injectionText("process.detail.injection.value.unknown",
                                 QStringLiteral("未知"));
        }
        const double bytes = static_cast<double>(value.value);
        if (value.value < 1024ULL)
        {
            return injectionText("process.detail.injection.size.bytes",
                                 QStringLiteral("%1 字节"))
                .arg(static_cast<qulonglong>(value.value));
        }
        if (value.value < 1024ULL * 1024ULL)
        {
            return QStringLiteral("%1 KB").arg(bytes / 1024.0, 0, 'f', 1);
        }
        if (value.value < 1024ULL * 1024ULL * 1024ULL)
        {
            return QStringLiteral("%1 MB").arg(bytes / (1024.0 * 1024.0), 0, 'f', 1);
        }
        return QStringLiteral("%1 GB").arg(bytes / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    }

    // 权限从 "RWX" 改成 "可读可写可执行"。三个字母对用户不是自解释的。
    QString humanProtectionText(const ev::RegionProtection& protection)
    {
        if (!protection.rawValue.present)
        {
            return injectionText("process.detail.injection.value.unknown",
                                 QStringLiteral("未知"));
        }
        const ev::ProtectionFacts facts = ev::ClassifyWin32Protection(protection.rawValue);
        if (facts.noAccess)
        {
            return injectionText("process.detail.injection.protect.no_access",
                                 QStringLiteral("不可访问"));
        }
        if (facts.unrecognizedBase)
        {
            return protectionText(protection);
        }
        const bool executable = ev::ExecuteProtectionIsExecutable(facts.execute);
        if (facts.writable && executable)
        {
            return injectionText("process.detail.injection.protect.rwx",
                                 QStringLiteral("可写＋可执行"));
        }
        if (executable)
        {
            return injectionText("process.detail.injection.protect.rx",
                                 QStringLiteral("可执行"));
        }
        if (facts.writable)
        {
            return injectionText("process.detail.injection.protect.rw",
                                 QStringLiteral("可写"));
        }
        return injectionText("process.detail.injection.protect.ro",
                             QStringLiteral("只读"));
    }

    QString humanRegionTypeText(const ev::RegionType type)
    {
        switch (type)
        {
        case ev::RegionType::Image:
            return injectionText("process.detail.injection.region.image",
                                 QStringLiteral("模块映像"));
        case ev::RegionType::Mapped:
            return injectionText("process.detail.injection.region.mapped",
                                 QStringLiteral("映射文件"));
        case ev::RegionType::Private:
            return injectionText("process.detail.injection.region.private",
                                 QStringLiteral("私有内存"));
        case ev::RegionType::Unknown:
        default:
            return injectionText("process.detail.injection.value.unknown",
                                 QStringLiteral("未知"));
        }
    }

    // 详情面板：分段 + 段内小标题，机器味的 key=value 一律压到最后一段。
    QString readableFindingDetailText(const ev::InjectionFinding& finding)
    {
        QStringList lines;
        lines << ruleText(finding.ruleId);
        const QString meaning = ruleMeaningText(finding.ruleId);
        if (!meaning.isEmpty())
        {
            lines << meaning;
        }
        lines << QString();

        lines << injectionText("process.detail.injection.detail.section.where",
                               QStringLiteral("【位置】"));
        lines << injectionText("process.detail.injection.detail.address_line",
                               QStringLiteral("    地址 %1，大小 %2，类型 %3，权限 %4"))
                     .arg(hex64(finding.address))
                     .arg(humanSizeText(finding.size))
                     .arg(humanRegionTypeText(finding.regionType))
                     .arg(humanProtectionText(finding.protection));
        if (!finding.moduleName.empty())
        {
            lines << injectionText("process.detail.injection.detail.module_line",
                                   QStringLiteral("    所属模块 %1"))
                         .arg(QString::fromStdString(finding.moduleName));
        }
        if (!finding.sectionName.empty() || finding.rva.present)
        {
            lines << injectionText("process.detail.injection.detail.section_line",
                                   QStringLiteral("    模块内位置：节 %1，偏移 %2"))
                         .arg(finding.sectionName.empty()
                                  ? QStringLiteral("-")
                                  : QString::fromStdString(finding.sectionName))
                         .arg(hex64(finding.rva));
        }
        if (!finding.mappedPath.empty())
        {
            lines << injectionText("process.detail.injection.detail.path_line",
                                   QStringLiteral("    对应文件 %1"))
                         .arg(QString::fromStdString(finding.mappedPath));
        }
        else
        {
            lines << injectionText("process.detail.injection.detail.no_path_line",
                                   QStringLiteral("    这块内存不对应任何磁盘文件"));
        }
        if (!finding.relatedThreads.empty())
        {
            QStringList threads;
            for (const ev::ThreadInstanceId& thread : finding.relatedThreads)
            {
                threads << QString::number(thread.tid.valueOr(0U));
            }
            lines << injectionText("process.detail.injection.detail.thread_line",
                                   QStringLiteral("    相关线程 %1"))
                         .arg(threads.join(QStringLiteral("、")));
        }
        lines << QString();

        lines << injectionText("process.detail.injection.detail.section.howsure",
                               QStringLiteral("【这条有多可靠】"));
        lines << QStringLiteral("    ") + confidenceText(finding.confidence);
        if (finding.confidence == ev::EvidenceConfidence::InputIncomplete)
        {
            lines << injectionText("process.detail.injection.detail.incomplete_hint",
                                   QStringLiteral("    采集时有数据没拿到，这条不能单独拿来下判断。"));
        }
        if (finding.exception.match == ev::ExceptionMatch::Matched)
        {
            lines << injectionText("process.detail.injection.detail.exception_line",
                                   QStringLiteral("    已被已知例外规则解释（规则 %1），按预期行为处理。"))
                         .arg(QString::fromStdString(finding.exception.ruleId));
        }
        if (!finding.coverageGapKeys.empty())
        {
            lines << injectionText("process.detail.injection.detail.gap_line",
                                   QStringLiteral("    这条本身还带着没查成的部分："));
            for (const std::string& gap : finding.coverageGapKeys)
            {
                lines << QStringLiteral("        · ") + gapText(gap);
            }
        }
        lines << QString();

        lines << injectionText("process.detail.injection.detail.section.time",
                               QStringLiteral("【时间与来源】"));
        lines << injectionText("process.detail.injection.detail.observed_line",
                               QStringLiteral("    首次观测到：%1（这是本次看到它的时间，不是注入发生的时间）"))
                     .arg(firstObservedText(finding.firstObservedUtc100ns));
        lines << injectionText("process.detail.injection.detail.injector_line",
                               QStringLiteral("    是谁放进来的：未知。事后看内存查不出注入者，要查这个必须有事前的实时记录。"));
        lines << QString();

        lines << injectionText("process.detail.injection.detail.section.raw",
                               QStringLiteral("【技术细节】以下是原始记录，供需要深挖时核对"));
        lines << injectionText("process.detail.injection.detail.raw_rule",
                               QStringLiteral("    规则 %1 v%2，检测器 %3"))
                     .arg(QString::fromStdString(finding.ruleId))
                     .arg(finding.ruleVersion)
                     .arg(QString::fromStdString(finding.detectorVersion));
        for (const std::string& fact : finding.facts)
        {
            lines << QStringLiteral("    ") + QString::fromStdString(fact);
        }
        return lines.join(QChar('\n'));
    }

    void showInjectionTraceDialog(QWidget* const parent,
                                  const ks::process::InjectionTraceResult& result,
                                  const QString& processName)
    {
        QDialog dialog(parent);
        dialog.setWindowTitle(
            injectionText("process.detail.injection.dialog.title",
                          QStringLiteral("%1注入检查 - %2"))
                .arg(result.requestedMode == ev::SurveyMode::Deep
                         ? injectionText("process.detail.injection.mode.deep_prefix",
                                         QStringLiteral("深度"))
                         : injectionText("process.detail.injection.mode.fast_prefix",
                                         QStringLiteral("快速")))
                .arg(processName));
        dialog.resize(1240, 780);

        QVBoxLayout* const layout = new QVBoxLayout(&dialog);
        layout->setContentsMargins(10, 10, 10, 10);
        layout->setSpacing(8);

        const ev::SurveyReport& report = result.report;
        const QString failure = failureText(result);

        // 顶部三行，一行一件事：结论是什么 / 这句话不能被读成什么 / 这次实际扫了多少。
        // 原来是"结论 + 11 个数字挤成一句 + 四行边界说明"，看不动。
        QLabel* const conclusionLabel = new QLabel(&dialog);
        conclusionLabel->setWordWrap(true);
        if (!failure.isEmpty())
        {
            conclusionLabel->setText(
                injectionText("process.detail.injection.headline.not_run",
                              QStringLiteral("这次检查没有执行")));
            conclusionLabel->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700; font-size:16px;")
                    .arg(KswordTheme::WarningHex()));
        }
        else
        {
            conclusionLabel->setText(conclusionHeadline(report.conclusion));
            conclusionLabel->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700; font-size:16px;")
                    .arg(KswordTheme::ThemeColorName(conclusionColor(report.conclusion))));
        }
        layout->addWidget(conclusionLabel);

        QLabel* const caveatLabel = new QLabel(&dialog);
        caveatLabel->setWordWrap(true);
        caveatLabel->setText(failure.isEmpty() ? conclusionCaveatText(report.conclusion)
                                               : failure);
        caveatLabel->setStyleSheet(QStringLiteral("color:%1;")
                                       .arg(KswordTheme::TextPrimaryHex()));
        layout->addWidget(caveatLabel);

        QLabel* const statsLabel = new QLabel(&dialog);
        statsLabel->setWordWrap(true);
        if (failure.isEmpty())
        {
            const QString elapsed =
                result.elapsedMs >= 1000ULL
                    ? injectionText("process.detail.injection.stats.seconds",
                                    QStringLiteral("%1 秒"))
                          .arg(static_cast<double>(result.elapsedMs) / 1000.0, 0, 'f', 1)
                    : injectionText("process.detail.injection.stats.milliseconds",
                                    QStringLiteral("%1 毫秒"))
                          .arg(result.elapsedMs);
            statsLabel->setText(
                injectionText("process.detail.injection.stats.line",
                              QStringLiteral("%1　用时 %2　扫过 %3 块内存、%4 个模块、%5 个线程，逐字节比对了 %6 段代码"))
                    .arg(result.requestedMode == ev::SurveyMode::Deep
                             ? injectionText("process.detail.injection.mode.deep",
                                             QStringLiteral("深度检查"))
                             : injectionText("process.detail.injection.mode.fast",
                                             QStringLiteral("快速检查")))
                    .arg(elapsed)
                    .arg(result.regionCount)
                    .arg(result.loaderModuleCount)
                    .arg(result.threadCount)
                    .arg(result.comparedRangeCount));
            if (report.stackThreadsWalked != 0U)
            {
                // 只在真做了栈回溯时才出这一行。walked 远小于 threadCount 是常态，
                // 所以要说清楚原因，否则会被读成"漏查了一大半线程"。
                statsLabel->setText(
                    statsLabel->text() +
                    injectionText("process.detail.injection.stats.stack_line",
                                  QStringLiteral("\n另查了 %1 个停着的线程的调用栈（共 %2 个线程；运行中的线程读到的调用栈不可信，只查停着的），其中 %3 个拿到了可信结果"))
                        .arg(report.stackThreadsWalked)
                        .arg(result.threadCount)
                        .arg(report.stackThreadsTrusted));
            }
        }
        else if (!result.diagnosticText.isEmpty())
        {
            statsLabel->setText(injectionText("process.detail.injection.report.diagnostic",
                                              QStringLiteral("技术信息：%1"))
                                    .arg(result.diagnosticText));
        }
        statsLabel->setStyleSheet(QStringLiteral("color:%1;")
                                      .arg(KswordTheme::TextSecondaryHex()));
        layout->addWidget(statsLabel);

        QTabWidget* const tabs = new QTabWidget(&dialog);

        // --- 发现了什么 ---
        QWidget* const findingPage = new QWidget(tabs);
        QVBoxLayout* const findingLayout = new QVBoxLayout(findingPage);
        findingLayout->setContentsMargins(0, 0, 0, 0);
        // 按规则分组的树。一个进程上"动态/非映像可执行内存"实测能到 874 条，
        // 平铺成 874 行 × 10 列谁也读不完；折成一个可展开的分组，标题行先告诉
        // 用户这一类是什么意思、有多少条，要看细节再展开。
        QTreeWidget* const tree = new QTreeWidget(findingPage);
        const QStringList headers{
            injectionText("process.detail.injection.header.item",
                          QStringLiteral("发现的内容")),
            injectionText("process.detail.injection.header.address", QStringLiteral("地址")),
            injectionText("process.detail.injection.header.size", QStringLiteral("大小")),
            injectionText("process.detail.injection.header.protect", QStringLiteral("权限")),
            injectionText("process.detail.injection.header.type", QStringLiteral("内存类型")),
            injectionText("process.detail.injection.header.note", QStringLiteral("备注"))
        };
        tree->setColumnCount(headers.size());
        tree->setHeaderLabels(headers);
        tree->setSelectionMode(QAbstractItemView::SingleSelection);
        tree->setUniformRowHeights(true);
        tree->setAlternatingRowColors(true);
        tree->setRootIsDecorated(true);

        // 分组顺序沿用判据层给出的顺序（先出现的规则排在前面），不做任何重排序，
        // 免得看起来像按"严重程度"排——本层不产生严重程度。
        std::vector<std::string> ruleOrder;
        std::map<std::string, std::vector<std::size_t>> groupedIndices;
        for (std::size_t index = 0; index < report.findings.size(); ++index)
        {
            const std::string& ruleId = report.findings[index].ruleId;
            if (groupedIndices.find(ruleId) == groupedIndices.end())
            {
                ruleOrder.push_back(ruleId);
            }
            groupedIndices[ruleId].push_back(index);
        }

        constexpr int kFindingIndexRole = Qt::UserRole + 1;
        // 展开阈值：条目多的分组默认折起来，少的直接摊开，免得还要手动点。
        constexpr std::size_t kAutoExpandLimit = 12U;
        for (const std::string& ruleId : ruleOrder)
        {
            const std::vector<std::size_t>& indices = groupedIndices[ruleId];
            std::size_t explainedCount = 0;
            for (const std::size_t index : indices)
            {
                if (report.findings[index].explainedByException())
                {
                    ++explainedCount;
                }
            }

            QTreeWidgetItem* const groupItem = new QTreeWidgetItem(tree);
            groupItem->setText(0, injectionText("process.detail.injection.group.title",
                                                QStringLiteral("%1 — %2 处"))
                                      .arg(ruleText(ruleId))
                                      .arg(indices.size()));
            groupItem->setData(0, kFindingIndexRole, -1);
            if (explainedCount > 0)
            {
                groupItem->setText(5, injectionText("process.detail.injection.group.explained",
                                                    QStringLiteral("其中 %1 处已被已知例外解释"))
                                          .arg(explainedCount));
            }
            QFont groupFont = groupItem->font(0);
            groupFont.setBold(true);
            groupItem->setFont(0, groupFont);
            const QString meaning = ruleMeaningText(ruleId);
            if (!meaning.isEmpty())
            {
                // 整行 tooltip：鼠标停在分组上就知道这一类是什么，不用先展开再猜。
                for (int column = 0; column < headers.size(); ++column)
                {
                    groupItem->setToolTip(column, meaning);
                }
            }

            for (const std::size_t index : indices)
            {
                const ev::InjectionFinding& finding = report.findings[index];
                QTreeWidgetItem* const item = new QTreeWidgetItem(groupItem);
                item->setText(0, findingHeadlineText(finding));
                item->setText(1, hex64(finding.address));
                item->setText(2, humanSizeText(finding.size));
                item->setText(3, humanProtectionText(finding.protection));
                item->setText(4, humanRegionTypeText(finding.regionType));
                if (finding.explainedByException())
                {
                    item->setText(5, injectionText("process.detail.injection.note.explained",
                                                   QStringLiteral("已被已知例外解释")));
                }
                else if (finding.confidence == ev::EvidenceConfidence::InputIncomplete)
                {
                    item->setText(5, injectionText("process.detail.injection.note.incomplete",
                                                   QStringLiteral("采集不完整，不能单独作判断")));
                }
                else if (finding.confidence ==
                         ev::EvidenceConfidence::CorroboratedIndependent)
                {
                    item->setText(5, injectionText("process.detail.injection.note.corroborated",
                                                   QStringLiteral("有多个独立来源互相印证")));
                }
                item->setData(0, kFindingIndexRole, static_cast<qulonglong>(index));
                // 例外命中的条目保留但降色：可核对，不再作为未解释项。
                const QColor color = finding.explainedByException()
                    ? KswordTheme::TextSecondaryColor()
                    : (finding.confidence == ev::EvidenceConfidence::InputIncomplete
                           ? KswordTheme::WarningColor()
                           : KswordTheme::TextPrimaryColor());
                for (int column = 0; column < headers.size(); ++column)
                {
                    item->setForeground(column, QBrush(color));
                }
            }
            groupItem->setExpanded(indices.size() <= kAutoExpandLimit);
        }

        tree->setColumnWidth(0, 300);
        tree->setColumnWidth(1, 150);
        tree->setColumnWidth(2, 90);
        tree->setColumnWidth(3, 110);
        tree->setColumnWidth(4, 90);
        tree->setColumnWidth(5, 220);
        findingLayout->addWidget(tree, 1);

        CodeEditorWidget* const detailPane = new CodeEditorWidget(findingPage);
        detailPane->setReadOnly(true);
        detailPane->setMaximumHeight(260);
        const QString emptyDetailText =
            failure.isEmpty()
                ? injectionText("process.detail.injection.dialog.no_finding",
                                QStringLiteral("这次没有找出需要解释的东西。这不等于「没有被注入过」——只说明在「查了什么」页列出的范围内没发现。选中上面任意一条可以在这里看它的完整信息。"))
                : failure;
        detailPane->setReportText(
            report.findings.empty() ? emptyDetailText
                                    : readableFindingDetailText(report.findings.front()));
        findingLayout->addWidget(detailPane);
        QObject::connect(
            tree, &QTreeWidget::currentItemChanged, &dialog,
            [detailPane, report, emptyDetailText](QTreeWidgetItem* const current,
                                                  QTreeWidgetItem*) {
                if (current == nullptr)
                {
                    return;
                }
                const QVariant stored = current->data(0, kFindingIndexRole);
                if (!stored.isValid() || stored.toLongLong() < 0)
                {
                    // 选中的是分组标题：这时给这一类的整体说明，而不是留着上一条不动。
                    const QString meaning = current->toolTip(0);
                    detailPane->setReportText(meaning.isEmpty() ? emptyDetailText : meaning);
                    return;
                }
                const std::size_t index = static_cast<std::size_t>(stored.toULongLong());
                if (index < report.findings.size())
                {
                    detailPane->setReportText(
                        readableFindingDetailText(report.findings[index]));
                }
            });
        tabs->addTab(findingPage,
                     injectionText("process.detail.injection.tab.findings",
                                   QStringLiteral("发现了什么 (%1)"))
                         .arg(report.findings.size()));

        // --- 查了什么、没查成什么 ---
        // 原来是 [已完成的检查] / [检查缺口] / [能力限制] 三张裸清单。清单本身没问题，
        // 问题是没人知道"缺口"和"限制"差在哪儿——所以每一块前面补一句人话解释。
        CodeEditorWidget* const coveragePane = new CodeEditorWidget(tabs);
        coveragePane->setReadOnly(true);
        {
            QStringList lines;
            if (report.scopeIntact)
            {
                lines << injectionText(
                    "process.detail.injection.coverage.intro_intact",
                    QStringLiteral("这次打算查的都查成了，所以上面那句结论是站得住的。"));
            }
            else
            {
                lines << injectionText(
                    "process.detail.injection.coverage.intro_broken",
                    QStringLiteral("有本来要查的东西没查成，所以这次不可能给出「没发现问题」——哪怕什么都没找到，也只能说「没查全」。没查成的原因列在下面。"));
            }
            lines << QString();

            lines << injectionText("process.detail.injection.coverage.section.gaps",
                                   QStringLiteral("■ 本来要查、但没查成的（这些会让结论打折扣）"));
            if (report.coverageGapKeys.empty())
            {
                lines << injectionText("process.detail.injection.coverage.none_gap",
                                       QStringLiteral("    没有，这次要查的都查到了。"));
            }
            for (const std::string& key : report.coverageGapKeys)
            {
                lines << QStringLiteral("    · ") + gapText(key);
            }
            lines << QString();

            lines << injectionText("process.detail.injection.coverage.section.done",
                                   QStringLiteral("■ 这次实际做了哪些检查"));
            if (report.completedCheckKeys.empty())
            {
                lines << injectionText("process.detail.injection.coverage.none_done",
                                       QStringLiteral("    一项都没做成。"));
            }
            for (const std::string& key : report.completedCheckKeys)
            {
                lines << QStringLiteral("    · ") + checkText(key);
            }
            lines << QString();

            lines << injectionText("process.detail.injection.coverage.section.skipped",
                                   QStringLiteral("■ 这次没做的检查"));
            if (report.notPerformedCheckKeys.empty())
            {
                lines << injectionText("process.detail.injection.coverage.none_skipped",
                                       QStringLiteral("    没有，该做的都做了。"));
            }
            for (const std::string& key : report.notPerformedCheckKeys)
            {
                lines << QStringLiteral("    · ") + checkText(key);
            }
            lines << QString();

            lines << injectionText("process.detail.injection.coverage.section.limits",
                                   QStringLiteral("■ 这个版本本来就不做的事（不影响上面的结论，只是说明它管到哪儿为止）"));
            if (report.capabilityLimitKeys.empty())
            {
                lines << injectionText("process.detail.injection.coverage.none_limit",
                                       QStringLiteral("    无。"));
            }
            for (const std::string& key : report.capabilityLimitKeys)
            {
                lines << QStringLiteral("    · ") + limitText(key);
            }
            coveragePane->setReportText(lines.join(QChar('\n')));
        }
        tabs->addTab(coveragePane,
                     injectionText("process.detail.injection.tab.coverage",
                                   QStringLiteral("查了什么 (%1 项没查成)"))
                         .arg(report.coverageGapKeys.size()));

        // --- 结果怎么读 ---
        // 边界说明从顶部四行挪到这里，和"能说什么/不能说什么"合成一页：两者讲的
        // 是同一件事，分在两处反而要求用户自己拼。
        CodeEditorWidget* const semanticsPane = new CodeEditorWidget(tabs);
        semanticsPane->setReadOnly(true);
        {
            QStringList lines;
            lines << injectionText("process.detail.injection.semantics.section.boundary",
                                   QStringLiteral("■ 这个功能能回答什么、不能回答什么"));
            lines << injectionText(
                "process.detail.injection.semantics.boundary_can",
                QStringLiteral("    能回答：这块内存里有没有来路不明的代码、某个模块的代码是不是和磁盘上的原件不一样。"));
            lines << injectionText(
                "process.detail.injection.semantics.boundary_cannot",
                QStringLiteral("    不能回答：是哪个进程、在什么时候、用什么手法放进来的。这些要靠事前的实时记录，翻事后的内存翻不出来。"));
            lines << injectionText(
                "process.detail.injection.semantics.boundary_time",
                QStringLiteral("    时间字段一律是「本次第一次看到它」的时间，不是注入发生的时间。"));
            lines << QString();

            lines << injectionText("process.detail.injection.semantics.section.observation",
                                   QStringLiteral("■ 这次看到的现象，各自能支撑到什么程度"));
            if (report.observations.empty())
            {
                lines << injectionText("process.detail.injection.semantics.none",
                                       QStringLiteral("    这次没有取得任何可用观测。"));
            }
            for (const ev::ObservationClass observation : report.observations)
            {
                lines << QStringLiteral("    · ") + observationText(observation);
                lines << QString();
            }
            semanticsPane->setReportText(lines.join(QChar('\n')));
        }
        tabs->addTab(semanticsPane,
                     injectionText("process.detail.injection.tab.semantics",
                                   QStringLiteral("结果怎么读")));

        layout->addWidget(tabs, 1);

        QHBoxLayout* const buttonLayout = new QHBoxLayout();
        buttonLayout->addStretch(1);
        QPushButton* const copyButton = new QPushButton(
            QIcon(":/Icon/process_copy_row.svg"),
            injectionText("process.detail.injection.action.copy_report",
                          QStringLiteral("复制报告")),
            &dialog);
        QPushButton* const closeButton = new QPushButton(
            injectionText("process.detail.injection.action.close", QStringLiteral("关闭")),
            &dialog);
        copyButton->setStyleSheet(buildBlueButtonStyle());
        closeButton->setStyleSheet(buildBlueButtonStyle());
        buttonLayout->addWidget(copyButton);
        buttonLayout->addWidget(closeButton);
        layout->addLayout(buttonLayout);

        const QString reportText = buildReportText(result, processName);
        QObject::connect(copyButton, &QPushButton::clicked, &dialog, [reportText]() {
            QApplication::clipboard()->setText(reportText);
        });
        QObject::connect(closeButton, &QPushButton::clicked, &dialog, &QDialog::accept);

        if (tree->topLevelItemCount() > 0)
        {
            tree->setCurrentItem(tree->topLevelItem(0));
        }
        dialog.exec();
    }
}

void ProcessDetailWindow::requestAsyncInjectionTraceScan(const bool deepMode)
{
    if (m_injectionTraceRunning)
    {
        return;
    }

    m_injectionTraceRunning = true;
    const std::uint64_t localTicket = ++m_injectionTraceTicket;
    // 两个按钮共用一次扫描，所以一起禁用：只灰掉被点的那个，会让人以为另一个还能点。
    if (m_injectionTraceButton != nullptr)
    {
        m_injectionTraceButton->setEnabled(false);
    }
    if (m_injectionTraceDeepButton != nullptr)
    {
        m_injectionTraceDeepButton->setEnabled(false);
    }
    updateModuleStatusLabel(
        deepMode ? injectionText("process.detail.injection.status.scanning_deep",
                                 QStringLiteral("● 正在做深度注入检查，可能要一两分钟..."))
                 : injectionText("process.detail.injection.status.scanning",
                                 QStringLiteral("● 正在做快速注入检查...")),
        true);

    const std::uint32_t pid = m_baseRecord.pid;
    const std::uint64_t creationTime100ns = m_baseRecord.creationTime100ns;
    const QString fallbackImagePath = QString::fromStdString(m_baseRecord.imagePath);
    const QString processName = QString::fromStdString(m_baseRecord.processName);

    kLogEvent scanStartEvent;
    info << scanStartEvent
        << "[ProcessDetailWindow] injection trace scan start, pid="
        << pid
        << ", creationTime100ns="
        << creationTime100ns
        << ", deep="
        << (deepMode ? 1 : 0)
        << eol;

    QPointer<ProcessDetailWindow> guard(this);
    QRunnable* const task = QRunnable::create([
        guard,
        localTicket,
        pid,
        creationTime100ns,
        fallbackImagePath,
        processName,
        deepMode]()
    {
        ks::process::InjectionTraceOptions options;
        options.deepMode = deepMode;
        if (deepMode)
        {
            // 深度模式要比较全部可执行映像范围，预算随之放宽；命中上限仍然会
            // 在报告里显示成截断，而不是悄悄变成"干净"。
            options.maxDurationMs = 120000ULL;
            options.maxReadBytes = 512ULL * 1024ULL * 1024ULL;
        }
        const ks::process::InjectionTraceResult result =
            ks::process::ScanProcessInjectionTrace(
                pid, creationTime100ns, fallbackImagePath, options);
        if (guard == nullptr)
        {
            return;
        }

        QMetaObject::invokeMethod(
            guard,
            [guard, localTicket, pid, processName, result]()
            {
                if (guard == nullptr || localTicket != guard->m_injectionTraceTicket)
                {
                    return;
                }

                guard->m_injectionTraceRunning = false;
                if (guard->m_injectionTraceButton != nullptr)
                {
                    guard->m_injectionTraceButton->setEnabled(true);
                }
                if (guard->m_injectionTraceDeepButton != nullptr)
                {
                    guard->m_injectionTraceDeepButton->setEnabled(true);
                }

                if (result.completed())
                {
                    guard->updateModuleStatusLabel(
                        injectionText(
                            "process.detail.injection.status.completed",
                            QStringLiteral("● %1，列出 %2 条待看的内容"))
                            .arg(conclusionHeadline(result.report.conclusion))
                            .arg(result.report.findings.size()),
                        false);
                }
                else
                {
                    guard->updateModuleStatusLabel(
                        injectionText("process.detail.injection.status.failed",
                                      QStringLiteral("● 注入检查没能执行：打不开这个进程，或者它已经换了一个")),
                        false);
                    if (guard->m_moduleStatusLabel != nullptr)
                    {
                        guard->m_moduleStatusLabel->setStyleSheet(
                            buildStateLabelStyle(statusErrorColor(), 700));
                    }
                }

                kLogEvent scanFinishEvent;
                info << scanFinishEvent
                    << "[ProcessDetailWindow] injection trace scan finish, pid="
                    << pid
                    << ", status="
                    << static_cast<int>(result.status)
                    << ", conclusion="
                    << Ksword::Evidence::AnalysisConclusionName(result.report.conclusion)
                    << ", findings="
                    << result.report.findings.size()
                    << ", gaps="
                    << result.report.coverageGapKeys.size()
                    << ", elapsedMs="
                    << result.elapsedMs
                    << eol;

                showInjectionTraceDialog(guard, result, processName);
            },
            Qt::QueuedConnection);
    });
    task->setAutoDelete(true);
    QThreadPool::globalInstance()->start(task);
}
