#pragma once

#include <QByteArray>
#include <QString>
#include <QUuid>

#include <functional>
#include <optional>

namespace ks::action_analyze
{
    // 由证据所有者核验后的采样身份，菜单请求按值持有。
    struct ObjectSampleRef
    {
        QUuid projectId; // 项目身份。
        QUuid sampleId; // 采样身份。

        bool operator==(const ObjectSampleRef&) const = default;
    };

    // 进程对象的采样内标识和已核验的实例字段。
    struct ProcessObjectRef
    {
        quint64 objectId = 0; // 采样内进程对象 ID。
        QString machineId; // 进程实例所属机器。
        QString bootId; // 进程实例所属启动代次。
        quint32 pid = 0; // Windows 进程 ID。
        quint64 createTime100ns = 0; // 进程创建 FILETIME。

        bool operator==(const ProcessObjectRef&) const = default;
    };

    // 线程实例中的 owner 由同采样的已核验引用解析取得。
    struct ThreadObjectRef
    {
        quint64 objectId = 0; // 采样内线程对象 ID。
        quint64 ownerObjectId = 0; // 记录声明的所属进程对象 ID。
        quint32 tid = 0; // Windows 线程 ID。
        quint64 createTime100ns = 0; // 线程创建 FILETIME。

        bool operator==(const ThreadObjectRef&) const = default;
    };

    // 调用方仅可从已验证的强身份填充字段。弱引用及裸 PID/TID 应保留在原证据视图。
    struct ObjectSelection
    {
        ObjectSampleRef sample; // 对象实际归属的项目及采样。
        ProcessObjectRef process; // 选中进程，或选中线程所属进程。
        std::optional<ThreadObjectRef> thread; // 有值即仅选择此线程。

        // 检查必需字段和线程 owner 一致性，返回能否作为菜单对象。
        bool isValid() const;
        bool operator==(const ObjectSelection&) const = default;
    };

    enum class DiagnosticFormat
    {
        ProcessMinidump,      // 已归档的 Windows 用户态进程 Minidump 原文件。
        ThreadDiagnosticJson // 已归档且仅包含所选线程的 UTF-8 JSON 诊断文档。
    };

    // 归档所有者提供已解析、已绑定身份及范围的描述，不从文件名猜测归属。
    struct ArchivedDiagnostic
    {
        ObjectSelection subject; // 归档记录实际关联的对象，须与请求精确一致。
        DiagnosticFormat format = DiagnosticFormat::ProcessMinidump; // 已登记的真实字节格式。
        QString evidenceId; // 已核验的归档证据 ID。
        QString archiveRoot; // 只读归档目录的绝对路径。
        QString sourcePath; // 已解析的归档文件绝对路径，应在 archiveRoot 下。
        qint64 size = 0; // 归档声明的实得字节数。
        QByteArray sha256; // 归档声明的原始 32 字节 SHA-256。
        bool partial = false; // 采集时仅有部分数据，与导出字节完整性分开。
        QString limitReason; // 可展示的归档缺口原因，partial 时须提供。

        bool operator==(const ArchivedDiagnostic&) const = default;
    };

    enum class DiagnosticExportStatus
    {
        Saved,
        SavedPartial,
        Canceled,
        InvalidEvidence,
        InvalidDestination,
        SourceMissing,
        SourceReadFailed,
        SourceMismatch,
        WriteFailed
    };

    struct DiagnosticExportResult
    {
        DiagnosticExportStatus status = DiagnosticExportStatus::InvalidEvidence; // 实际导出终态。
        qint64 bytes = 0; // 已提交的字节数，仅成功时非零。
        QString detail; // 可选文件系统错误文本。
    };

    // 仅比较值与格式范围，供菜单能力判断及写入前复核；无文件 I/O。
    bool MatchesArchivedDiagnostic(const ObjectSelection& subject, const ArchivedDiagnostic& archive);

    // 在工作线程导出归档原字节。输入冻结对象、证据及用户路径；返回本次独立导出回执。
    DiagnosticExportResult ExportArchivedDiagnostic(const ObjectSelection& subject, const ArchivedDiagnostic& archive,
        const QString& destination, const std::function<bool()>& isCanceled = {});
}
