#include "DumpAutoCheck.h"

// ============================================================
// DumpAutoCheck.cpp
// 说明：
// - "与 KSword 有关"的判定刻意分层：只出现在已加载模块表里不算证据，
//   因为 KSword 运行期间它必然在表里，据此提示上报只会制造噪音；
//   真正有意义的是出现在肇事候选、调用栈或已卸载模块表里；
// - 上报指引强调"触发流程"：没有复现步骤的崩溃报告基本无法定位，
//   而用户往往只贴一个停止码，所以把要写什么逐条列出来。
// ============================================================

#include "DumpSymbolIndex.h"
#include "MinidumpFormat.h"
#include "../Internationalization/LanguageManager.h"

#include <QDir>
#include <QFileInfo>
#include <QSet>

#include <algorithm>

namespace ks::minidump
{
    namespace
    {
        // kKswordModulePrefix：KSword 自有模块的统一前缀。
        // 驱动产物为 KswordARK.sys，用户态为
        // Ksword5.1.exe / KswordARKLight.exe / KswordHUD.exe 等，
        // 前缀匹配比逐个枚举更耐改名。
        const QString kKswordModulePrefix = QStringLiteral("ksword");

        // kExtraKswordModules：不带 ksword 前缀、但确属本项目的组件。
        const char* const kExtraKswordModules[] = {
            "apimonitor_x64.dll",
        };

        // IsKswordModule 作用：判断模块名是否属于 KSword 自身组件。
        // 传入 moduleName 模块名或完整路径；比较只看文件名部分且不区分大小写。
        bool IsKswordModule(const QString& moduleName)
        {
            const QString baseName = BaseModuleName(moduleName).trimmed().toLower();
            if (baseName.isEmpty())
            {
                return false;
            }
            if (baseName.startsWith(kKswordModulePrefix))
            {
                return true;
            }
            for (const char* const extraName : kExtraKswordModules)
            {
                if (baseName == QString::fromLatin1(extraName))
                {
                    return true;
                }
            }
            return false;
        }

        // AppendMatched 作用：把命中的模块名去重后加入列表。
        void AppendMatched(QStringList& matched, const QString& moduleName)
        {
            const QString baseName = BaseModuleName(moduleName).trimmed();
            if (baseName.isEmpty())
            {
                return;
            }
            for (const QString& existing : matched)
            {
                if (existing.compare(baseName, Qt::CaseInsensitive) == 0)
                {
                    return;
                }
            }
            matched.append(baseName);
        }

        // ScanDumpDirectory 作用：把一个目录里的转储文件并入候选集合。
        // 传入 directoryPath 目录、cutoffTime 时间下界与输出参数；
        // 目录不存在时静默返回——没装过转储或从未蓝屏都是正常状态。
        void ScanDumpDirectory(
            const QString& directoryPath,
            const QDateTime& cutoffTime,
            RecentDumpInfo& best)
        {
            QDir directory(directoryPath);
            if (!directory.exists())
            {
                return;
            }
            const QFileInfoList entries = directory.entryInfoList(
                QStringList{ QStringLiteral("*.dmp") },
                QDir::Files | QDir::Readable,
                QDir::Time);
            for (const QFileInfo& entry : entries)
            {
                const QDateTime modifiedTime = entry.lastModified();
                if (!modifiedTime.isValid() || modifiedTime < cutoffTime)
                {
                    continue;
                }
                ++best.totalRecentCount;
                if (best.found && best.modifiedTime >= modifiedTime)
                {
                    continue;
                }
                best.found = true;
                best.filePath = QDir::toNativeSeparators(entry.absoluteFilePath());
                best.modifiedTime = modifiedTime;
                best.fileSizeBytes = entry.size();
                best.isKernelDump = true;
            }
        }

        // ScanSingleDumpFile 作用：把一个具体转储文件并入候选集合。
        void ScanSingleDumpFile(
            const QString& filePath,
            const QDateTime& cutoffTime,
            RecentDumpInfo& best)
        {
            const QFileInfo entry(filePath);
            if (!entry.exists() || !entry.isFile() || !entry.isReadable())
            {
                return;
            }
            const QDateTime modifiedTime = entry.lastModified();
            if (!modifiedTime.isValid() || modifiedTime < cutoffTime)
            {
                return;
            }
            ++best.totalRecentCount;
            if (best.found && best.modifiedTime >= modifiedTime)
            {
                return;
            }
            best.found = true;
            best.filePath = QDir::toNativeSeparators(entry.absoluteFilePath());
            best.modifiedTime = modifiedTime;
            best.fileSizeBytes = entry.size();
            best.isKernelDump = true;
        }
    }

    RecentDumpInfo FindRecentDump(const int maxAgeHours)
    {
        RecentDumpInfo best{};
        const int effectiveHours = maxAgeHours > 0 ? maxAgeHours : 24;
        const QDateTime cutoffTime =
            QDateTime::currentDateTime().addSecs(-static_cast<qint64>(effectiveHours) * 3600);

        // 系统目录取自环境变量而不是硬编码 C:\Windows：
        // 系统盘不在 C: 的机器并不罕见。
        QString windowsDirectory = qEnvironmentVariable("SystemRoot");
        if (windowsDirectory.isEmpty())
        {
            windowsDirectory = qEnvironmentVariable("windir");
        }
        if (windowsDirectory.isEmpty())
        {
            windowsDirectory = QStringLiteral("C:/Windows");
        }

        const QDir windowsDir(windowsDirectory);
        ScanDumpDirectory(windowsDir.filePath(QStringLiteral("Minidump")), cutoffTime, best);
        ScanSingleDumpFile(windowsDir.filePath(QStringLiteral("MEMORY.DMP")), cutoffTime, best);
        return best;
    }

    KswordRelevance EvaluateKswordRelevance(const DumpParseResult& result)
    {
        KswordRelevance relevance{};

        // 第一层：肇事模块候选。归因加权后仍指向 KSword，是最强的信号。
        for (const BlameEntry& blame : result.analysis.blame)
        {
            if (IsKswordModule(blame.moduleName))
            {
                relevance.inBlameList = true;
                AppendMatched(relevance.matchedModules, blame.moduleName);
            }
        }

        // 第二层：疑似调用栈。栈扫描有误报，但 KSword 模块出现在栈上仍值得追。
        for (const StackFrameEntry& frame : result.stackFrames)
        {
            if (IsKswordModule(frame.moduleName))
            {
                relevance.inStack = true;
                AppendMatched(relevance.matchedModules, frame.moduleName);
            }
        }

        // 第三层：已卸载模块表。KSword 驱动卸载后仍被命中，通常意味着
        // 卸载路径上有没取消干净的回调或挂起操作。
        for (const UnloadedModuleEntry& unloaded : result.unloadedModules)
        {
            if (IsKswordModule(unloaded.name))
            {
                relevance.inUnloadedList = true;
                AppendMatched(relevance.matchedModules, unloaded.name);
            }
        }

        relevance.related =
            relevance.inBlameList || relevance.inStack || relevance.inUnloadedList;

        if (!relevance.related)
        {
            // 只在已加载模块表里出现不算证据：KSword 运行期间它必然在表里。
            for (const ModuleEntry& moduleEntry : result.modules)
            {
                if (IsKswordModule(moduleEntry.name))
                {
                    relevance.onlyLoaded = true;
                    AppendMatched(relevance.matchedModules, moduleEntry.name);
                }
            }
            return relevance;
        }

        if (relevance.inBlameList)
        {
            relevance.summary = QStringLiteral(
                "归因结果把 KSword 组件列为肇事模块候选，这是最强的关联信号。");
        }
        else if (relevance.inUnloadedList)
        {
            relevance.summary = QStringLiteral(
                "崩溃现场命中了已卸载的 KSword 驱动，通常意味着卸载时有回调或挂起操作未取消。");
        }
        else
        {
            relevance.summary = QStringLiteral(
                "疑似调用栈上出现了 KSword 组件的地址。栈扫描存在误报，"
                "但仍建议上报由开发者复核。");
        }
        return relevance;
    }

    QString KswordQqGroupUrl()
    {
        return QStringLiteral("https://qm.qq.com/q/5tWNPfIxkk");
    }

    QString KswordIssuesUrl()
    {
        return QStringLiteral("https://github.com/KSwordDEV/KSword/issues");
    }

    QString BuildKswordReportGuidance(
        const KswordRelevance& relevance,
        const QString& dumpFilePath)
    {
        QStringList lines;
        lines.append(ks::i18n::sourceText(relevance.summary));
        if (!relevance.matchedModules.isEmpty())
        {
            lines.append(ks::i18n::sourceText(QStringLiteral("命中组件：%1"))
                .arg(relevance.matchedModules.join(ks::i18n::text(
                    QStringLiteral("minidump.report.module_separator"),
                    QStringLiteral("、")))));
        }
        lines.append(QString());
        lines.append(ks::i18n::sourceText(
            QStringLiteral("这属于 KSword 自身的问题，请反馈给开发者。提交时请一并说明：")));
        lines.append(ks::i18n::sourceText(QStringLiteral(
            "1. 崩溃前你在 KSword 里做了什么：打开了哪个页面、点了哪个功能、"
            "目标进程/驱动/文件是什么；")));
        lines.append(ks::i18n::sourceText(
            QStringLiteral("2. 是否可以稳定复现，以及复现的具体步骤；")));
        lines.append(ks::i18n::sourceText(
            QStringLiteral("3. 当时 R0 驱动是否已启用，是否刚做过加载/卸载操作；")));
        lines.append(ks::i18n::sourceText(
            QStringLiteral("4. 系统版本与 KSword 版本；")));
        lines.append(ks::i18n::sourceText(
            QStringLiteral("5. 附上本页的“导出报告”结果，必要时附转储文件本身。")));
        if (!dumpFilePath.isEmpty())
        {
            lines.append(ks::i18n::sourceText(
                QStringLiteral("   转储文件：%1")).arg(dumpFilePath));
        }
        lines.append(QString());
        lines.append(ks::i18n::sourceText(
            QStringLiteral("反馈渠道：QQ 群，或 GitHub Issues。")));
        return lines.join(QStringLiteral("\n"));
    }
}
