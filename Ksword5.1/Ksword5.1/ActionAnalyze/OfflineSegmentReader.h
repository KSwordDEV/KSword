#pragma once

#include "OfflineProjectReader.h"

#include <optional>

namespace ks::action_analyze
{
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
        std::optional<quint64> threadId; // 未解析的线程对象引用。
    };

    enum class SegmentEnd
    {
        Complete,       // 到达只读文件的扫描边界。
        Unavailable,    // 文件无法读取。
        Truncated,      // 段尾不足以继续校验。
        Invalid,        // 封装或已支持正文损坏。
        Unsupported,    // 版本、编码或必需正文不受支持。
        PreviewLimit,   // 达到预览扫描配额。
        Canceled        // 调用方取消，结果不可发布。
    };

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
        QList<SegmentRow> rows; // 正文可理解的行和明确标记的可选不透明记录。
    };

    // 工作线程按路径只读扫描 Stored 段，返回配额内的不可变证据投影。
    SegmentSnapshot ReadOfflineSegment(const QString& path, const CancelCheck& isCanceled);
}
