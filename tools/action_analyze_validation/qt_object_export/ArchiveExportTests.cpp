#include "../../../Ksword5.1/Ksword5.1/ActionAnalyze/ObjectDiagnosticExport.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>

#include <cstdio>

using namespace ks::action_analyze;

namespace
{
    // 写入无真实系统或进程数据的夹具，返回字节是否全部落盘。
    bool WriteFixture(const QString& path, const QByteArray& bytes)
    {
        QFile file(path); // 固定测试目录下本次创建的文件。
        return file.open(QIODevice::WriteOnly) && file.write(bytes) == bytes.size() && file.flush();
    }

    // 读回目标字节，比较完整内容以验证原样复制、失败保留及部分标记。
    QByteArray ReadFixture(const QString& path)
    {
        QFile file(path); // 本次夹具或导出目标。
        return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
    }

    // 用固定合成的标识稳定生成测试对象，不查询本机进程。
    ObjectSelection SampleProcess()
    {
        ObjectSelection subject; // 合成采样内已解析进程引用。
        subject.sample = {QUuid(QStringLiteral("{11111111-1111-4111-8111-111111111111}")),
            QUuid(QStringLiteral("{22222222-2222-4222-8222-222222222222}"))};
        subject.process = {1, QStringLiteral("test-machine"), QStringLiteral("boot-1"), 100, 200};
        return subject;
    }

    // 根据本次夹具原字节填入与产品入口同型的已核验描述。
    ArchivedDiagnostic ArchiveFor(const ObjectSelection& subject, DiagnosticFormat format,
        const QString& root, const QString& source, const QByteArray& bytes)
    {
        ArchivedDiagnostic archive; // 测试证据的绝对路径及 SHA-256。
        archive.subject = subject;
        archive.format = format;
        archive.evidenceId = QStringLiteral("fixture-archive-id");
        archive.archiveRoot = root;
        archive.sourcePath = source;
        archive.size = bytes.size();
        archive.sha256 = QCryptographicHash::hash(bytes, QCryptographicHash::Sha256);
        return archive;
    }
}

// 无窗口测试。固定目录必须尚不存在，每次运行独占创建并精确删除夹具。
int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv); // 使用 Qt Core，不创建或操作 GUI。
    const QDir release(QCoreApplication::applicationDirPath()); // 复用统一正式 Release 的 Qt 依赖。
    const QString scratchName = QStringLiteral("ActionAnalyzeObjectExportFixture"); // 固定、唯一的测试数据目录。
    if (!release.mkdir(scratchName))
    {
        std::puts("FAIL: fixture directory already exists or cannot be created");
        return 1;
    }
    const QDir scratch(release.filePath(scratchName)); // 只在新建目录中操作测试文件。
    const QString sourceRoot = scratch.filePath(QStringLiteral("archive")); // 独立源归档目录。
    const QString source = QDir(sourceRoot).filePath(QStringLiteral("original")); // 合成归档原件。
    const QString out = scratch.filePath(QStringLiteral("export.dmp")); // 明确的导出端。
    const QString threadOut = scratch.filePath(QStringLiteral("thread.json")); // 线程证据导出端。
    int failed = 0; // 已失败的断言数。
    int checks = 0; // 已执行的断言数。
    const auto check = [&](bool ok, const char* name) {
        // 逐项报告，失败时继续验证其它路径与清理结果。
        ++checks;
        if (!ok)
        {
            ++failed;
            std::printf("FAIL: %s\n", name);
        }
    };

    check(scratch.mkdir(QStringLiteral("archive")), "create archive dir");
    const auto process = SampleProcess(); // 固定 PID 和创建时间的进程身份。
    auto thread = process; // 同一进程中的固定线程身份。
    thread.thread = ThreadObjectRef{2, process.process.objectId, 300, 400};
    QByteArray dump(2 * 1024 * 1024 + 17, '\0'); // 可跨三个读块的无内存夹具。
    dump.replace(0, 16, QByteArray::fromHex("4d444d5093a700000100000020000000")); // 只填入公开 Minidump 头字段。
    dump[dump.size() - 1] = 'z'; // 明确检查末尾块也被复制。
    const auto archived = ArchiveFor(process, DiagnosticFormat::ProcessMinidump, sourceRoot, source, dump); // 正确描述。

    check(process.isValid() && thread.isValid(), "valid process and thread");
    check(MatchesArchivedDiagnostic(process, archived), "match known process dump");
    check(!MatchesArchivedDiagnostic(thread, archived), "process dump must not export as a thread");
    auto wrongSample = process; // 保留原生 PID 但更换采样身份。
    wrongSample.sample.sampleId = wrongSample.sample.projectId;
    check(!MatchesArchivedDiagnostic(wrongSample, archived), "different sample with same PID");
    auto reusedProcess = process; // PID 不变但创建时间显示已复用。
    ++reusedProcess.process.createTime100ns;
    check(!MatchesArchivedDiagnostic(reusedProcess, archived), "reused PID");
    check(ExportArchivedDiagnostic(process, archived, out).status == DiagnosticExportStatus::SourceMissing, "missing source");
    check(WriteFixture(source, dump), "write fixture dump");
    const auto saved = ExportArchivedDiagnostic(process, archived, out); // 完整输出字节回执。
    check(saved.status == DiagnosticExportStatus::Saved && saved.bytes == dump.size(), "reported save status and bytes");
    check(ReadFixture(out) == dump, "minidump exported byte for byte");

    auto corrupted = archived; // SHA-256 错误，旧目标必须保留。
    corrupted.sha256[0] = ~corrupted.sha256.at(0);
    check(ExportArchivedDiagnostic(process, corrupted, out).status == DiagnosticExportStatus::SourceMismatch, "hash mismatch");
    check(ReadFixture(out) == dump, "hash mismatch preserves existing destination");
    const auto archiveOutput = ExportArchivedDiagnostic(process, archived, source); // 归档路径不可写。
    check(archiveOutput.status == DiagnosticExportStatus::InvalidDestination && ReadFixture(source) == dump, "protect source directory");
    const auto badPath = scratch.filePath(QStringLiteral("missing-dir/export.dmp")); // 目录缺失会触发真实系统写入失败。
    check(ExportArchivedDiagnostic(process, archived, badPath).status == DiagnosticExportStatus::WriteFailed, "write failure");
    unsigned cancelPolls = 0; // 允许首块落入暂存文件，再请求取消。
    check(ExportArchivedDiagnostic(process, archived, out, [&] { return ++cancelPolls == 3; }).status
        == DiagnosticExportStatus::Canceled && ReadFixture(out) == dump, "cancel after one block preserves destination");

    const QByteArray json("{\n  \"tid\": 300,\n  \"source\": \"synthetic test\"\n}\n"); // 模拟已作用域限定的线程证据原文。
    auto threadArchive = ArchiveFor(thread, DiagnosticFormat::ThreadDiagnosticJson, sourceRoot, source, json);
    threadArchive.partial = true;
    check(!MatchesArchivedDiagnostic(thread, threadArchive), "partial archive requires a reason");
    threadArchive.limitReason = QStringLiteral("fixture coverage limit");
    check(MatchesArchivedDiagnostic(thread, threadArchive), "match scoped thread diagnostic");
    auto reusedThread = thread; // 线程创建时间不同，其他标识故意保持相同。
    ++reusedThread.thread->createTime100ns;
    check(!MatchesArchivedDiagnostic(reusedThread, threadArchive), "reused TID");
    auto wrongOwner = thread; // 归属进程不同。
    ++wrongOwner.thread->ownerObjectId;
    check(!wrongOwner.isValid(), "reject wrong owner process");
    check(WriteFixture(source, json), "write scoped JSON fixture");
    const auto partial = ExportArchivedDiagnostic(thread, threadArchive, threadOut); // 只有部分采集，完整复制所登记的原文件。
    check(partial.status == DiagnosticExportStatus::SavedPartial && partial.bytes == json.size(), "explicit partial receipt");
    check(ReadFixture(threadOut) == json, "scoped evidence exported byte for byte");

    const QByteArray wrongJson("[0]"); // 合法 JSON 数组也不满足诊断文档对象形式。
    check(WriteFixture(source, wrongJson), "write wrong JSON fixture");
    const auto wrongDocument = ArchiveFor(thread, DiagnosticFormat::ThreadDiagnosticJson, sourceRoot, source, wrongJson);
    check(ExportArchivedDiagnostic(thread, wrongDocument, threadOut).status == DiagnosticExportStatus::SourceMismatch
        && ReadFixture(threadOut) == json, "wrong JSON format preserves prior output");

    // 无递归删除。若出现意外文件，清理失败并保留路径供核对。
    check(QFile::remove(source) && QFile::remove(out) && QFile::remove(threadOut), "remove fixture and output files");
    check(scratch.rmdir(QStringLiteral("archive")) && release.rmdir(scratchName), "remove empty fixture directories");
    std::printf("Archive export: %d/%d passed\n", checks - failed, checks);
    return failed ? 1 : 0;
}
