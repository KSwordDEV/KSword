#pragma once

#include "OfflineProjectReader.h"
#include "../../../KswordCLI/ActionAnalyze/Archive/NetworkEvidenceArchive.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectCallbackEvidence.h"
#include "../../../shared/evidence/ApiMonitorClue.h"
#include "../../../shared/evidence/ApiInjectionFields.h"
#include "../../../shared/evidence/ApiApcFields.h"
#include "../../../shared/evidence/ApiContextFields.h"
#include "../../../shared/evidence/ApiSectionMapFields.h"
#include "../../../shared/evidence/ApiMemoryLifecycleFields.h"
#include "../../../shared/evidence/ApiTransferCandidateWindow.h"
#include "../../../shared/evidence/ApiNativeExecutionProjection.h"
#include "../../../KswordCLI/ActionAnalyze/Rules/ApiBehaviorObservation.h"

#include <QByteArray>
#include <optional>

namespace ks::action_analyze
{
    // 实时或归档的 ETW 事件头，文件时间与接收 QPC 分开保存。
    struct LiveEtwHeader
    {
        QString provider; // 已启用的来源 GUID。
        quint64 fileTime = 0; // ETW 报头的 UTC FILETIME。
        quint16 eventId = 0; // 来源事件描述符编号。
        quint8 version = 0; // 来源事件描述符版本。
        quint8 opcode = 0; // 来源操作码。
    };

    // 归档 ETW 行额外保留的采集代次和实际字节前缀。
    struct SegmentEtwPayload
    {
        QString sourceEpoch; // 来源声明的采集代次。
        std::optional<quint64> qpcFrequencyHz; // 归档报告的接收时钟频率。
        quint16 originalBytes = 0; // ETW 报头说明的原始载荷长度。
        quint32 storedBytes = 0; // 从实际内联数据核对的归档长度。
        bool malformed = false; // 采集端报告的载荷异常。
        QByteArray preview; // 用于详情的有限十六进制预览输入。
    };

    // 归档 API 只保留来源事实。报头 PID/TID 表示调用方，无法据此确定目标。
    struct SegmentApiClue
    {
        QString api; // 原包中的精确导出名。
        QString family; // 共用分类器返回的线索类别。
        quint64 time = 0; // API Monitor 原始 FILETIME。
        quint64 sourceSequence = 0; // JSONL 行号或合作来源流水号，由已核验的尾记区分。
        std::optional<quint64> callerCreation; // 源归档声明的调用方创建时间。
        QByteArray preview; // 详情控件显示的有界原包预览。
        std::optional<Ksword::Evidence::ApiMonitorMemoryWriteReturn> memoryWriteReturn; // 同一原包的显式返回值和状态。
        std::optional<Ksword::Evidence::ApiMonitorArchiveSource> archiveSource{}; // 由已核验的导入尾记或合作检查点声明。
        std::optional<Ksword::Evidence::ApiInjectionFieldsV1> apiTransfer{}; // 显式版本化 API 参数，不从摘要推断身份。
        Ksword::Evidence::ApiInjectionOutcome apiTransferOutcome = Ksword::Evidence::ApiInjectionOutcome::Unknown; // 按精确返回约定解释。
        std::optional<Ksword::Evidence::ApiApcFieldsV1> apiApc{}; // 独立 AAAP1 原包字段，不解释为 AAIP1。
        Ksword::Evidence::ApiApcQueueOutcome apcOutcome = Ksword::Evidence::ApiApcQueueOutcome::Unknown; // 仅为队列请求结果。
        std::optional<Ksword::Evidence::ApiContextFieldsV1> apiContext{}; // 当前原包显式 AACT1 请求字段。
        Ksword::Evidence::ApiContextOutcome contextOutcome = Ksword::Evidence::ApiContextOutcome::Unknown; // 原调用返回，不表示上下文生效。
        std::optional<Ksword::Evidence::ApiSectionMapFieldsV1> apiSectionMap{}; // 当前原包显式 AASM1 请求和返回字段。
        Ksword::Evidence::ApiSectionMapOutcome sectionMapOutcome = Ksword::Evidence::ApiSectionMapOutcome::Unknown; // 原映射调用返回，不表示写入或执行。
        std::optional<Ksword::Evidence::ApiMemoryLifecycleFieldsV1> apiMemoryLifecycle{}; // AAIM1本次内存生命周期。
        quint64 memorySourceSession = 0; // 原packet会话身份，不从当前活采补值。
        std::optional<Ksword::ActionAnalyze::Rules::ApiBehaviorObservation> behaviorObservation; // 原包独立参数与返回。
    };

    // 已核验的回调原包提示；目标 PID/TID 复用行字段，不是规范对象引用。
    struct SegmentCallbackObservation
    {
        quint64 sourceSequence = 0; // 回调环原生序号，独立于 Stored 记录号。
        qint64 timeUtc100ns = 0; // 原包报告的 UTC 时间，不进入接收 QPC 时间轴。
        std::optional<quint32> contextPid; // 回调上下文 PID 提示，原包为零时未知。
        std::optional<quint32> contextTid; // 回调上下文 TID 提示，原包为零时未知。
        quint64 inlineOffset = 0; // 同一归档段内原包的字节起点。
        quint32 inlineBytes = 0; // 经共享读侧核对的原包长度。
    };

    // 仅在首尾与整个文件核验通过后保存批次回执；零观测仍保留该回执。
    struct SegmentCallbackBatch
    {
        Ksword::ActionAnalyze::ProjectCallbackEvidencePlan plan; // 源代次与请求游标。
        Ksword::ActionAnalyze::ProjectCallbackEvidenceEnd end; // 源游标状态与可空漏失计数。
        quint64 blockOrdinal = 0; // 全批所在的 Stored 块号。
        QString sha256; // 已核验整段散列，用于区分同一采样的不同文件内容。
    };

    // 本端直接读取同一进程实例的计数差，缺失的 I/O 计数保持未知。
    struct LiveProcessObservation
    {
        quint64 creationTime = 0; // 原进程句柄的创建 FILETIME。
        quint64 elapsedMs = 0; // 前后两次读取之间的单调时间差。
        quint64 cpu100ns = 0; // 区间内内核及用户态 CPU 时间之和。
        std::optional<quint64> readBytes; // 进程报告的读 I/O 字节差。
        std::optional<quint64> writeBytes; // 进程报告的写 I/O 字节差。
    };
    // 回调结束后只保留已验证的值及有限字节预览。
    struct SegmentNetworkEvidence
    {
        ks::cli::action_analyze::archive::NetworkArchivedFlow flow; // 已检查的记录及保留长度。
        ks::cli::action_analyze::archive::NetworkEvidenceBinding source; // 归档中的声明范围。
        ks::cli::action_analyze::archive::NetworkSourceTrust sourceTrust; // 来源验证级别。
        quint64 inlineFileOffset = 0; // 本文件内对应的已验证起点。
        QByteArray preview; // 从同一块复制的前缀，非完整载荷声明。
    };

    // 表内数值来自已校验的段头、记录头或已理解的正文。
    struct SegmentRow
    {
        quint64 sequence = 0; // 封装记录序号；项目多段回放中跨段连续。
        quint64 offset = 0; // 记录头在源文件中的字节位置。
        quint64 segmentOrdinal = 0; // 归档行的源文件段号；实时行保持零。
        quint16 type = 0; // Stored 记录类型编号。
        quint16 version = 0; // 正文模式版本。
        bool decoded = false; // 是否存在可用的正文投影。
        quint32 payloadBytes = 0; // 记录头声明且已校验的正文长度。
        std::optional<quint64> ordinal; // 正文中的 CanonicalEvent 序号。
        std::optional<quint64> receiveQpc; // 原始接收 QPC tick。
        std::optional<quint32> pid; // 可用的来源头 PID。
        std::optional<quint32> tid; // 可用的来源头 TID。
        std::optional<quint16> category; // CanonicalEvent 类别编号。
        std::optional<quint32> eventKind; // CanonicalEvent 种类编号。
        std::optional<quint64> sourceId; // 未解析的来源字典引用。
        std::optional<quint64> actorId; // 未解析的进程对象引用。
        std::optional<quint64> targetId; // 未解析的目标进程对象引用。
        std::optional<quint64> threadId; // 未解析的线程对象引用。
        std::optional<SegmentNetworkEvidence> network; // 已知网络记录的只读证据。
        std::optional<LiveEtwHeader> liveEtw; // 实时与归档共用的 ETW 事件头。
        std::optional<SegmentEtwPayload> archivedEtw; // 仅从已校验的原始段复制。
        std::optional<SegmentApiClue> archivedApi; // 归档 API 线索及原事件坐标。
        std::optional<SegmentCallbackObservation> archivedCallback; // 仅作来源上下文的回调提示及坐标。
        std::optional<LiveProcessObservation> liveProcess; // 预设进程活动分析的区间观测。
        std::optional<quint64> liveSourceSequence; // Qt 自写档保留的原观测序号，丢弃会形成间隔。
        Ksword::ActionAnalyze::ProjectEvidenceLane evidenceLane = Ksword::ActionAnalyze::ProjectEvidenceLane::Primary; // 项目原始通道，独立文件和实时行使用默认值。
    };

    // 只在同一快照内比较；通道、段和原序号共同定位原包，不能用其中一项代替。
    struct SegmentRowAnchor
    {
        Ksword::ActionAnalyze::ProjectEvidenceLane lane; // 归档目录的类型化身份。
        quint64 segment; // 该通道中的实际段号。
        quint64 sequence; // 原记录序号，实时行则为同一采样的内存序号。

        bool operator==(const SegmentRowAnchor&) const = default;
    };

    // 从当前行取选择锚；返回值不借用行内存，可跨过滤和重读保留。
    inline SegmentRowAnchor RowAnchor(const SegmentRow& row)
    {
        return {row.evidenceLane, row.segmentOrdinal, row.sequence};
    }

    // 将已绑定的项目通道转成稳定目录名，供详情和关系坐标共用。
    inline QString RawLaneName(Ksword::ActionAnalyze::ProjectEvidenceLane lane)
    {
        return lane == Ksword::ActionAnalyze::ProjectEvidenceLane::MixedEtw
            ? QStringLiteral("raw-etw") : QStringLiteral("raw");
    }

    enum class SegmentEnd
    {
        Complete,       // 独立段或旧档读完；已提交项目回放到达经验证的终段。
        Unavailable,    // 文件无法读取。
        Truncated,      // 段尾不足以继续校验。
        Invalid,        // 封装或已支持正文损坏。
        Unsupported,    // 版本、编码或必需正文不受支持。
        PreviewLimit,   // 达到预览扫描配额。
        Canceled,       // 调用方取消，结果不可发布。
        WrongSample,    // 文件超出绑定项目或段头身份不匹配。
        InvalidCheckpoint, // 项目检查点或所引用的证据无法验证。
        IncompleteSample, // 仅有已验证的中间段，或连续采样首段尚未发布。
        InvalidCallbackBatch, // 已识别回调格式，但专用读侧未核验完整批次。
        CallbackProjectRequired // 独立文件无法核对回调批次冻结采样描述。
    };

    // 双流检查点与 Qt 整个 raw 文件有各自的核验边界，采样终态以 SegmentEnd 为准。
    enum class SegmentCheckpoint { NotRequested, Unpublished, Verified, Pending, QtRawVerified, ApiRawVerified, ApiLegacyUnpublished };
    enum class SegmentProjection { Overview, ApiClues }; // 总览保留原始行，规则只保留分类线索。

    // API 和 ETW 的段、端点及完成状态独立。总览绝不使用一条全局水位表示两路。
    struct MixedArchiveReadback
    {
        SegmentEnd apiEnd = SegmentEnd::Unavailable; // API 主通道的终态，主快照其他标量仍属于 API。
        SegmentEnd etwEnd = SegmentEnd::Unavailable; // 独立 ETW 检查点读回结果。
        quint64 etwLastOrdinal = 0; // 最后一个已验证的 ETW 段。
        quint64 etwVerifiedRows = 0; // 已验 ETW 原始记录数，含封装元数据。
        quint64 etwFailedOrdinal = 0; // 无法核验的 ETW 段，零表示没有坏段。
        quint64 etwFailureOffset = 0; // ETW 坏段的已知偏移，零表示未定位。
    };

    struct SegmentSnapshot
    {
        QString path; // 独立文件路径，或项目回放的首段路径（用于稳定的重读身份）。
        QString projectId; // 段头记录的项目 UUID。
        QString sampleId; // 段头记录的采样 UUID。
        QString sampleDescriptionHash; // 项目回放实际核验的采样描述散列；独立段或实时预览为空。
        quint64 ordinal = 0; // 入口段号，零表示无已发布结果；项目回放有结果时固定为 1。
        quint32 stream = 0; // 段头中的流类型。
        quint64 fileBytes = 0; // 最近已验证段的文件大小，独立段为该文件大小。
        quint64 prefixBytes = 0; // 同段已验证的字节端点。
        quint64 failureOffset = 0; // 首个停止位置，单位字节。
        SegmentEnd end = SegmentEnd::Unavailable; // 扫描结束原因。
        SegmentCheckpoint checkpoint = SegmentCheckpoint::NotRequested; // 检查点读取结果。
        QList<SegmentRow> rows; // 正文可理解的行和明确标记的可选不透明记录。
        bool live = false; // 同一总览中的实时投影，与磁盘归档独立。
        quint64 liveRevision = 0; // 本次实时来源累计接纳的记录数，滚动淘汰后仍递增。
        bool hasArchivedEtw = false; // 当前行窗口中至少有一条可识别的归档 ETW 记录。
        bool hasArchivedApi = false; // 已通过导入尾记或 API 跟随检查点的分类记录。
        std::optional<SegmentCallbackBatch> callbackBatch; // 核验通过的回调批次，包括完整空批次。
        std::optional<quint64> apiFollowSourceRows; // API 跟随的来源水位，包含未分类原包，单位由来源决定。
        QString apiStartupJson; // 已核验终段中的历史启动回执全文，旧档为空，不跟随当前进程变化。
        std::optional<Ksword::Evidence::ApiMonitorArchiveSource> apiArchiveSource; // 最新核验的 API 检查点来源，含零线索段。
        QString recordedRuleSourceSha256; // 已核验采集计划的规则内容摘要，旧档缺失时为空。
        quint64 verifiedApiClueRows = 0; // 连续核验的 API 线索总数，含被最近窗口移出的线索。
        quint64 lastVerifiedOrdinal = 0; // 项目回放的连续提交水位。
        quint64 verifiedRows = 0; // 项目已验证的累计行数，含被最近窗口移出的行。
        quint64 failedOrdinal = 0; // 本次无法验证的段号，零表示无坏段。
        std::optional<quint64> qtArchiveDropped; // 只在 Qt 终止记录通过核验后公布归档队列丢弃数。
        std::optional<MixedArchiveReadback> mixed; // 仅总览从已核验 API 混采计划派生，并实际回读 ETW 通道。
        std::vector<Ksword::Evidence::ApiTransferCandidateRows<SegmentRow>> transferCandidates; // 后台核验的最近写入/创建双方。
        quint64 transferCandidateCount = 0; // 已核验前缀的全部区间候选数，含窗口淘汰。
        std::vector<Ksword::Evidence::ApiApcCandidateRows<SegmentRow>> apcTransferCandidates; // 独立保留最近 128 对 APC 双方。
        quint64 apcTransferCandidateCount = 0; // 全部已核验 APC 候选，含裁剪部分。
        std::vector<Ksword::Evidence::ApiContextCandidateRows<SegmentRow>> contextTransferCandidates; // 最近 128 对上下文候选双方。
        quint64 contextTransferCandidateCount = 0; // 已核验前缀累计数，含窗口外候选。
        quint64 evictedTransferWrites = 0; // 共享 1024 写入链窗口已淘汰数。
        std::vector<Ksword::Evidence::ApiSectionMapCandidateRow<SegmentRow>> sectionMapRequests; // 范围/入口各128条的独立原行窗口。
        quint64 evictedSectionMaps = 0; // 范围及入口请求输入的累计裁剪数，沿用旧字段名。
        Ksword::Evidence::ApiNativeExecutionProjection<SegmentRow> nativeExecution; // 同采样后台执行候选与状态。
        bool nativeHistoryOnly = false; // 采样只有独立原生历史，普通raw缺失不伪造API/ETW终段。
    };

    // 从已冻结的目录请求计算 raw/1 的规范路径，非法项目或采样标识返回空字符串。
    QString SampleRawSegmentPath(const SampleRequest& sample);

    // 工作线程按路径只读扫描 Stored 段，返回配额内的不可变证据投影。
    // 可选目录请求校验冻结的项目、采样及连续检查点，仅保留最近窗口中的已验证行。
    // maxProjectSegments 为零时读取整个已发布范围，否则到预算时返回经过验证的前缀。
    // ApiClues 对被动 API 跟随独立保留最近分类观测，完整验证仍由同一检查点读侧承担。
    SegmentSnapshot ReadOfflineSegment(const QString& path, const CancelCheck& isCanceled,
        const SampleRequest* expected = nullptr, quint64 maxProjectSegments = 0,
        SegmentProjection projection = SegmentProjection::Overview);
}
