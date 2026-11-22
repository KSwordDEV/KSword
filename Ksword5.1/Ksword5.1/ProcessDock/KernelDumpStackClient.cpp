#include "KernelDumpStackClient.h"

#include <QCoreApplication>
#include <QDir>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>

using namespace ks::kernel_dump;

// 输入是点击执行时冻结的参数；输出仅接受同一转储和目标的正式 CLI 回执。
ThreadStackResult RunKernelDumpStackCli(const ThreadStackRequest& request)
{
    ThreadStackResult result; // 失败回执亦保留请求来源和目标。
    result.dumpPath = request.dumpPath;
    result.processId = request.processId;
    result.threadId = request.threadId;
    result.status = ThreadStackStatus::EngineUnavailable;
    const auto path = QDir::toNativeSeparators(QString::fromStdWString(request.dumpPath)); // CLI 需要本地绝对路径。
    QStringList arguments{QStringLiteral("process"), QStringLiteral("thread"), QStringLiteral("stack"),
        QStringLiteral("dump"), QStringLiteral("--dump"), path, QStringLiteral("--pid"), QString::number(request.processId),
        QStringLiteral("--tid"), QString::number(request.threadId), QStringLiteral("--limit"), QString::number(request.frameLimit),
        QStringLiteral("--json")}; // 按参数传递，不调用 shell。
    if (request.processCreationTime100ns)
    {
        arguments << QStringLiteral("--creation-time") << QString::number(request.processCreationTime100ns);
    }
    if (request.threadCreationTime100ns)
    {
        arguments << QStringLiteral("--thread-creation-time") << QString::number(request.threadCreationTime100ns);
    }
    if (!request.symbolPath.empty())
    {
        arguments << QStringLiteral("--symbols") << QString::fromStdWString(request.symbolPath);
    }

    // 单次 CLI 进程不复用 GUI 的调试器模块，也不从 PATH 查找程序。
    QProcess child;
    const auto executable = QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("KswordCLI.exe"));
    child.start(executable, arguments, QIODevice::ReadOnly);
    if (!child.waitForStarted(5000))
    {
        result.diagnostic = L"Cannot start the adjacent KswordCLI.exe.";
        return result;
    }
    if (!child.waitForFinished(90000))
    {
        child.kill();
        child.waitForFinished(3000);
        result.diagnostic = L"Kernel dump unwind exceeded 90 seconds.";
        return result;
    }

    // 校验封套、来源及目标；异常退出或未知格式时不发布任何帧。
    const auto output = child.readAllStandardOutput();
    const auto exitCode = child.exitCode();
    result.diagnostic = L"Invalid kernel dump response from KswordCLI.exe.";
    if (child.exitStatus() != QProcess::NormalExit || output.size() > 1024 * 1024)
    {
        return result;
    }
    const auto envelope = QJsonDocument::fromJson(output).object();
    const auto data = envelope.value(QStringLiteral("data")).toObject();
    if (envelope.value(QStringLiteral("schemaVersion")).toInt() != 1 ||
        data.value(QStringLiteral("source")).toString() != QStringLiteral("kernel_dump") ||
        data.value(QStringLiteral("live")).toBool(true) || data.value(QStringLiteral("dump")).toString() != path ||
        data.value(QStringLiteral("pid")).toInteger() != request.processId ||
        data.value(QStringLiteral("tid")).toInteger() != request.threadId)
    {
        return result;
    }
    const auto diagnostics = envelope.value(QStringLiteral("diagnostics")).toArray(); // CLI 人类可读状态。
    result.diagnostic = diagnostics.isEmpty() ? std::wstring{} : diagnostics.first().toString().toStdWString();
    result.dumpTimeUnixSeconds = static_cast<std::uint32_t>(data.value(QStringLiteral("dumpTimeUnixSeconds")).toInteger());
    result.threadCreationTime100ns = data.value(QStringLiteral("threadCreationTime")).toString().toULongLong();
    result.processCreationTime100ns = data.value(QStringLiteral("processCreationTime")).toString().toULongLong();
    result.limited = data.value(QStringLiteral("limited")).toBool();
    result.identityMatched = data.value(QStringLiteral("identityMatched")).toBool();
    if (exitCode != 0 && exitCode != 6)
    {
        result.status = exitCode == 2 ? ThreadStackStatus::EngineUnavailable : ThreadStackStatus::UnwindUnavailable;
        return result;
    }

    // 数值一律按十六进制字符串解析，避免 JSON 浮点数舍入内核地址。
    const auto frames = data.value(QStringLiteral("frames")).toArray();
    if (!result.identityMatched || frames.isEmpty() || frames.size() > request.frameLimit ||
        (request.threadCreationTime100ns && result.threadCreationTime100ns != request.threadCreationTime100ns) ||
        (request.processCreationTime100ns && result.processCreationTime100ns != request.processCreationTime100ns))
    {
        result.diagnostic = L"The CLI did not verify the requested identity and frame range.";
        return result;
    }
    for (const auto& item : frames)
    {
        const auto row = item.toObject(); // 一行对应一个有序 DbgEng 帧。
        ThreadStackFrame frame;
        frame.index = static_cast<std::uint32_t>(result.frames.size());
        frame.instruction = row.value(QStringLiteral("instruction")).toString().toULongLong(nullptr, 16);
        frame.stack = row.value(QStringLiteral("stack")).toString().toULongLong(nullptr, 16);
        if (row.value(QStringLiteral("index")).toInteger(-1) != frame.index || !(frame.instruction >> 63) || !(frame.stack >> 63))
        {
            result.frames.clear();
            result.diagnostic = L"The CLI returned an invalid kernel frame.";
            return result;
        }
        frame.returnAddress = row.value(QStringLiteral("returnAddress")).toString().toULongLong(nullptr, 16);
        frame.displacement = row.value(QStringLiteral("displacement")).toString().toULongLong(nullptr, 16);
        frame.module = row.value(QStringLiteral("module")).toString().toStdWString();
        frame.symbol = row.value(QStringLiteral("symbol")).toString().toStdWString();
        result.frames.push_back(std::move(frame));
    }
    result.status = exitCode == 0 ? ThreadStackStatus::Ok : ThreadStackStatus::Partial;
    return result;
}
