#include "FilePropertyPeAnalyzer.h"

// ============================================================
// FilePropertyPeAnalyzer.cpp
// 作用：
// - 保留 FileDock 属性窗口的 QString API；
// - 将 PE 读取、头部、节表、导入/导出/目录解析委托给 ks::file；
// - 属性页使用后端原生字段模型，文本 API 仅用于兼容导出。
// ============================================================

#include "../ksword/file/pe_analyzer.h"

#include <QSet>

#include <algorithm>
#include <string>
#include <utility>

namespace file_dock_detail
{
    namespace
    {
        // formatRvaText 作用：
        // - 把导入 thunk RVA 格式化为 UI 统一十六进制文本；
        // - 输入为后端安全解析出的 RVA，输出始终带 0x 前缀。
        QString formatRvaText(const std::uint32_t rvaValue)
        {
            return QStringLiteral("0x%1")
                .arg(rvaValue, 8, 16, QLatin1Char('0'))
                .toUpper();
        }
    }

    QString buildPeAnalysisText(const QString& filePath)
    {
        // 输入 filePath 来自 Qt UI；转换为 std::wstring 后交给非 UI 后端。
        // 返回值仍为 QString，以保持 FileDock 属性窗口调用点不变。
        const std::wstring reportText = ks::file::BuildPeAnalysisText(filePath.toStdWString());
        return QString::fromStdWString(reportText);
    }

    PropertyDocument buildPeAnalysisDocument(const QString& filePath)
    {
        const ks::file::PeAnalysisResult result =
            ks::file::AnalyzePeFile(filePath.toStdWString());
        PropertyDocument document;
        document.title = QStringLiteral("PE解析");
        int sectionIndex = -1;
        QVector<int> ancestors;
        for (const ks::file::PeReportEntry& entry : result.entries)
        {
            if (entry.kind == ks::file::PeReportEntry::Kind::Section)
            {
                document.section(QString::fromStdWString(entry.name));
                sectionIndex = static_cast<int>(document.nodes.size()) - 1;
                ancestors.clear();
                continue;
            }

            // Keep only indexes: appending QVector nodes can relocate them, so
            // no pointer to an earlier node survives across entries.
            const int depth = std::min<int>(static_cast<int>(entry.depth),
                static_cast<int>(ancestors.size()));
            QVector<PropertyNode>* destination = sectionIndex >= 0
                ? &document.nodes[sectionIndex].children : &document.nodes;
            for (int level = 0; level < depth; ++level)
            {
                destination = &(*destination)[ancestors[level]].children;
            }
            PropertyNode node;
            node.kind = entry.kind == ks::file::PeReportEntry::Kind::Note
                ? PropertyNode::Kind::Note : PropertyNode::Kind::Field;
            node.name = QString::fromStdWString(entry.name);
            node.value = QString::fromStdWString(entry.value);
            destination->push_back(std::move(node));
            if (entry.kind == ks::file::PeReportEntry::Kind::Field)
            {
                ancestors.resize(depth + 1);
                ancestors[depth] = static_cast<int>(destination->size()) - 1;
            }
        }
        return document;
    }

    PeDependencyResult analyzePeDependencies(const QString& filePath)
    {
        // 输入 filePath 来自属性窗口；处理逻辑复用 ks::file::AnalyzePeFile 的
        // PE32/PE32+ 头部和 Import Directory 安全解析；返回 Qt 表格模型。
        PeDependencyResult dependencyResult{};
        const ks::file::PeAnalysisResult analysisResult =
            ks::file::AnalyzePeFile(filePath.toStdWString());

        dependencyResult.success = analysisResult.success;
        dependencyResult.isPe = analysisResult.success;
        if (!analysisResult.success)
        {
            const QString reportText = QString::fromStdWString(analysisResult.errorText).trimmed();
            const bool clearlyNotPe =
                reportText.contains(QStringLiteral("不是有效的 MZ 文件")) ||
                reportText.contains(QStringLiteral("文件过小"));
            dependencyResult.isPe = !clearlyNotPe;
            dependencyResult.errorText = clearlyNotPe
                ? QStringLiteral("不适用：目标不是 EXE/DLL PE 文件。\n%1").arg(reportText)
                : QStringLiteral("PE 解析失败：Import Directory 无法读取。\n%1").arg(reportText);
            return dependencyResult;
        }

        QSet<QString> seenDllNames;
        for (const ks::file::PeImportModuleSummary& module : analysisResult.importModules)
        {
            const QString dllName = QString::fromStdString(module.dllName).trimmed();
            if (!dllName.isEmpty() && !seenDllNames.contains(dllName.toLower()))
            {
                seenDllNames.insert(dllName.toLower());
                dependencyResult.dllNames.push_back(dllName);
            }

            if (module.imports.empty())
            {
                PeDependencyRow row{};
                row.dllName = dllName;
                row.importMode = QStringLiteral("<无函数项>");
                row.diagnosticText = QString::fromStdString(module.diagnosticText);
                dependencyResult.rows.push_back(row);
                continue;
            }

            for (const ks::file::PeImportFunctionSummary& function : module.imports)
            {
                PeDependencyRow row{};
                row.dllName = QString::fromStdString(function.dllName);
                row.functionName = QString::fromStdString(function.functionName);
                row.importMode = function.importByOrdinal
                    ? QStringLiteral("Ordinal")
                    : QStringLiteral("Name");
                row.ordinalText = function.importByOrdinal
                    ? QString::number(function.ordinal)
                    : QStringLiteral("-");
                row.hintText = function.importByOrdinal
                    ? QStringLiteral("-")
                    : QString::number(function.hint);
                row.thunkRvaText = formatRvaText(function.thunkRva);
                row.diagnosticText = QString::fromStdString(module.diagnosticText);
                dependencyResult.rows.push_back(row);
            }
        }

        if (dependencyResult.dllNames.isEmpty() && dependencyResult.rows.isEmpty())
        {
            dependencyResult.errorText = QStringLiteral("该 PE 没有 Import Directory 或未声明依赖 DLL。");
        }
        return dependencyResult;
    }
}
