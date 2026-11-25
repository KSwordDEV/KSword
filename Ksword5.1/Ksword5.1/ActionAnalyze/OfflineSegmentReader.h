#pragma once

#include "OfflineProjectReader.h"
#include "../../../KswordCLI/ActionAnalyze/Archive/NetworkEvidenceArchive.h"

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
        quint64 sequence = 0; // 段内稳定记录身份。
        quint64 offset = 0; // 记录头在源文件中的字节位置。
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
        std::optional<LiveProcessObservation> liveProcess; // 预设进程活动分析的区间观测。
    };

    enum class SegmentEnd
    {
        Complete,       // 到达只读文件的扫描边界。
        Unavailable,    // 文件无法读取。
        Truncated,      // 段尾不足以继续校验。
        Invalid,        // 封装或已支持正文损坏。
        Unsupported,    // 版本、编码或必需正文不受支持。
        PreviewLimit,   // 达到预览扫描配额。
        Canceled,       // 调用方取消，结果不可发布。
        WrongSample,    // 文件超出绑定项目或段头身份不匹配。
        InvalidCheckpoint // 项目终态标记或所引用的证据无法验证。
    };

    // 项目入口明确区分旧档和已验证的终态。独立段没有项目检查点回执。
    enum class SegmentCheckpoint { NotRequested, Unpublished, Verified };

    struct SegmentSnapshot
    {
        QString path; // 用户选择的独立文件路径。
        QString projectId; // 段头记录的项目 UUID。
        QString sampleId; // 段头记录的采样 UUID。
        quint64 ordinal = 0; // 段号，零表示无可用段头。
        quint32 stream = 0; // 段头中的流类型。
        quint64 fileBytes = 0; // 文件起始大小。
        quint64 prefixBytes = 0; // 已通过本预览支持检查的记录端点。
        quint64 failureOffset = 0; // 首个停止位置，单位字节。
        SegmentEnd end = SegmentEnd::Unavailable; // 扫描结束原因。
        SegmentCheckpoint checkpoint = SegmentCheckpoint::NotRequested; // 检查点读取结果。
        QList<SegmentRow> rows; // 正文可理解的行和明确标记的可选不透明记录。
        bool live = false; // 同一总览中的未归档实时来源。
        bool hasArchivedEtw = false; // 预览前缀中至少有一条可识别的 ETW 记录。
    };

    // 从已冻结的目录请求计算 raw/1 的规范路径，非法项目或采样标识返回空字符串。
    QString SampleRawSegmentPath(const SampleRequest& sample);

    // 工作线程按路径只读扫描 Stored 段，返回配额内的不可变证据投影。
    // 可选目录请求校验冻结的项目、采样描述和终态检查点，再读取对应原始段。
    SegmentSnapshot ReadOfflineSegment(const QString& path, const CancelCheck& isCanceled,
        const SampleRequest* expected = nullptr);
}
