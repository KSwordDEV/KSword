#include "ObjectDiagnosticExport.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QSaveFile>
#include <QtEndian>

#include <algorithm>

namespace ks::action_analyze
{
namespace
{
    constexpr qint64 kReadChunkBytes = 1024 * 1024; // 固定块大小，与文件总长无关。
    constexpr qint64 kMinidumpHeaderBytes = 32; // MINIDUMP_HEADER 的字节数。
    constexpr qint64 kMinidumpDirectoryBytes = 12; // MINIDUMP_DIRECTORY 的条目字节数。
    constexpr qint64 kThreadDocumentMaxBytes = 4 * 1024 * 1024; // 对齐归档小文档上限。

    // 比较归一后的绝对路径及目录边界。Windows 按不区分大小写的语义处理。
    bool InsideDirectory(const QString& path, const QString& root)
    {
        if (path.isEmpty() || root.isEmpty())
        {
            return false;
        }
#ifdef Q_OS_WIN
        constexpr auto sensitivity = Qt::CaseInsensitive; // Windows 默认文件系统比较方式。
#else
        constexpr auto sensitivity = Qt::CaseSensitive; // 便携测试按本地路径精确匹配。
#endif
        const QString prefix = root.endsWith(u'/') ? root : root + u'/'; // 拒绝同名前缀的兄弟目录。
        return path.compare(root, sensitivity) == 0 || path.startsWith(prefix, sensitivity);
    }

    // 保持只读归档完整，拒绝归档目录内的输出及可解析到归档内的别名。
    bool OutputOutsideArchive(const QString& destination, const QString& root, const QString& configuredRoot)
    {
        const QFileInfo output(destination); // 用户实际选择的保存目标。
        if (!output.isAbsolute() || output.isDir() || output.fileName().isEmpty())
        {
            return false;
        }
        const QString lexicalPath = QDir::cleanPath(output.absoluteFilePath()); // 检查显式路径归属。
        const QString realParent = output.dir().canonicalPath(); // 解析目标所在目录的别名。
        const QString realOutput = output.canonicalFilePath(); // 已存在文件可能是独立链接。
        return !InsideDirectory(lexicalPath, configuredRoot) && !InsideDirectory(realParent, root)
            && !InsideDirectory(realOutput, root);
    }

    // 核对公开 Minidump 头及目录范围。具体流和对象归属由上游已核验描述负责。
    bool IsMinidumpHeader(const QByteArray& prefix, qint64 size)
    {
        if (prefix.size() < kMinidumpHeaderBytes || !prefix.startsWith("MDMP"))
        {
            return false;
        }
        const quint16 version = qFromLittleEndian<quint16>(prefix.constData() + 4); // 公开格式版本的低 16 位。
        const qint64 count = qFromLittleEndian<quint32>(prefix.constData() + 8); // 目录条目数。
        const qint64 directoryOffset = qFromLittleEndian<quint32>(prefix.constData() + 12); // 相对文件头的目录偏移。
        return version == 0xa793 && directoryOffset >= kMinidumpHeaderBytes && directoryOffset <= size
            && count <= (size - directoryOffset) / kMinidumpDirectoryBytes;
    }
}

bool ObjectSelection::isValid() const
{
    // 单独检查实例与所属关系，不用裸 PID/TID 自动补足字段。
    if (sample.projectId.isNull() || sample.sampleId.isNull() || !process.objectId || !process.pid
        || !process.createTime100ns || process.machineId.isEmpty() || process.bootId.isEmpty())
    {
        return false;
    }
    return !thread || (thread->objectId && thread->objectId != process.objectId && thread->tid
        && thread->createTime100ns && thread->ownerObjectId == process.objectId);
}

bool MatchesArchivedDiagnostic(const ObjectSelection& subject, const ArchivedDiagnostic& archive)
{
    if (!subject.isValid() || archive.subject != subject || archive.evidenceId.isEmpty()
        || archive.size <= 0 || archive.sha256.size() != 32 || (archive.partial && archive.limitReason.isEmpty())
        || !QDir::isAbsolutePath(archive.archiveRoot) || !QDir::isAbsolutePath(archive.sourcePath))
    {
        return false;
    }
    // 只允许精确单线程文档和进程 Minidump，拒绝把整个进程文件包装为线程证据。
    switch (archive.format)
    {
    case DiagnosticFormat::ProcessMinidump:
        return !subject.thread && archive.size >= kMinidumpHeaderBytes;
    case DiagnosticFormat::ThreadDiagnosticJson:
        return subject.thread.has_value() && archive.size <= kThreadDocumentMaxBytes;
    }
    return false;
}

DiagnosticExportResult ExportArchivedDiagnostic(const ObjectSelection& subject, const ArchivedDiagnostic& archive,
    const QString& destination, const std::function<bool()>& isCanceled)
{
    // 在触及源或目标前再次验证冻结的内容描述和取消状态。
    if (!MatchesArchivedDiagnostic(subject, archive))
    {
        return {DiagnosticExportStatus::InvalidEvidence};
    }
    if (isCanceled && isCanceled())
    {
        return {DiagnosticExportStatus::Canceled};
    }

    const QString root = QDir(archive.archiveRoot).canonicalPath(); // 已验证信任范围的实际目录。
    const QFileInfo source(archive.sourcePath); // 归档目录解析得到的唯一源路径。
    if (root.isEmpty())
    {
        return {DiagnosticExportStatus::SourceReadFailed};
    }
    if (!source.exists())
    {
        return {DiagnosticExportStatus::SourceMissing};
    }
    const QString sourcePath = source.canonicalFilePath(); // 仅导出解析后仍在归档目录中的普通文件。
    if (!source.isFile() || !InsideDirectory(sourcePath, root))
    {
        return {DiagnosticExportStatus::InvalidEvidence};
    }
    if (!OutputOutsideArchive(destination, root, QDir::cleanPath(archive.archiveRoot)))
    {
        return {DiagnosticExportStatus::InvalidDestination};
    }

    QFile input(sourcePath); // 只读同一个归档源句柄，并在复制后复核完整字节。
    if (!input.open(QIODevice::ReadOnly))
    {
        return {DiagnosticExportStatus::SourceReadFailed, 0, input.errorString()};
    }
    if (input.size() != archive.size)
    {
        return {DiagnosticExportStatus::SourceMismatch};
    }

    QSaveFile output(destination); // 核验成功前保留旧目标和未提交文件的原子回退。
    output.setDirectWriteFallback(false);
    if (!output.open(QIODevice::WriteOnly))
    {
        return {DiagnosticExportStatus::WriteFailed, 0, output.errorString()};
    }

    QCryptographicHash hash(QCryptographicHash::Sha256); // 实际复制字节的 SHA-256。
    QByteArray threadDocument; // 仅线程格式保留限长副本供 JSON 语法检查。
    qint64 copied = 0; // 已读并写入暂存文件的精确字节数。
    while (copied < archive.size)
    {
        if (isCanceled && isCanceled())
        {
            return {DiagnosticExportStatus::Canceled};
        }
        const QByteArray block = input.read((std::min)(archive.size - copied, kReadChunkBytes)); // 不越过声明边界。
        if (input.error() != QFileDevice::NoError)
        {
            return {DiagnosticExportStatus::SourceReadFailed, 0, input.errorString()};
        }
        if (block.isEmpty() || (copied == 0 && archive.format == DiagnosticFormat::ProcessMinidump
            && !IsMinidumpHeader(block, archive.size)))
        {
            return {DiagnosticExportStatus::SourceMismatch};
        }
        if (archive.format == DiagnosticFormat::ThreadDiagnosticJson)
        {
            threadDocument.append(block);
        }
        hash.addData(block);
        if (output.write(block) != block.size())
        {
            return {DiagnosticExportStatus::WriteFailed, 0, output.errorString()};
        }
        copied += block.size();
    }

    // 区分文件更改、格式不符和已登记的采集缺口，只有验证成功才提交。
    if (input.size() != copied || hash.result() != archive.sha256
        || (archive.format == DiagnosticFormat::ThreadDiagnosticJson && !QJsonDocument::fromJson(threadDocument).isObject()))
    {
        return {DiagnosticExportStatus::SourceMismatch};
    }
    if (isCanceled && isCanceled())
    {
        return {DiagnosticExportStatus::Canceled};
    }
    if (!output.commit())
    {
        return {DiagnosticExportStatus::WriteFailed, 0, output.errorString()};
    }
    return {archive.partial ? DiagnosticExportStatus::SavedPartial : DiagnosticExportStatus::Saved, copied};
}
}
