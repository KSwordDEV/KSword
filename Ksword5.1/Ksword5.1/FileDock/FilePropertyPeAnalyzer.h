#pragma once

// ============================================================
// FilePropertyPeAnalyzer.h
// 作用：
// 1) 为文件属性窗口提供 PE 原生结构字段模型；
// 2) 保留导入表、导出表、目录与区段概览及文本导出兼容；
// 3) 与 FileDock UI 解耦，便于后续继续扩展资源表/重定位表。
// ============================================================

#include <QString>
#include <QStringList>
#include <QVector>

#include "FilePropertyView.h"

namespace file_dock_detail
{
    // PeDependencyRow 作用：
    // - 把 ks::file 的导入表结构转换为 Qt UI 可直接显示的一行；
    // - 每行对应一个导入函数；仅 DLL 名称行也可通过 functionName 为空表示。
    struct PeDependencyRow
    {
        QString dllName;       // dllName：依赖 DLL 名称。
        QString functionName;  // functionName：函数名；按序号导入时为空。
        QString ordinalText;   // ordinalText：序号导入的 Ordinal 文本。
        QString hintText;      // hintText：名称导入的 Hint 文本。
        QString importMode;    // importMode：Name 或 Ordinal。
        QString thunkRvaText;  // thunkRvaText：Thunk/IAT RVA 文本。
        QString diagnosticText; // diagnosticText：该 DLL 或函数的解析诊断。
    };

    // PeDependencyResult 作用：
    // - 聚合“依赖 DLL”页需要的结构化数据和错误文本；
    // - success=false 时 errorText 可直接显示给用户。
    struct PeDependencyResult
    {
        bool success = false;       // success：PE 解析是否成功。
        bool isPe = false;          // isPe：目标是否为 PE；普通文本文件为 false。
        QString errorText;          // errorText：失败或不适用原因。
        QStringList dllNames;       // dllNames：去重后的依赖 DLL 名称。
        QVector<PeDependencyRow> rows; // rows：函数级导入项。
    };

    // buildPeAnalysisText 作用：
    // - 读取并解析指定文件的 PE 结构；
    // - 返回可直接显示到 CodeEditorWidget 的文本。
    // 参数 filePath：目标文件完整路径。
    // 返回：解析结果文本；若失败则返回可读错误说明。
    QString buildPeAnalysisText(const QString& filePath);

    // Build the property model directly from PE decoder entries, preserving
    // directory/item nesting without treating an exported report as data.
    PropertyDocument buildPeAnalysisDocument(const QString& filePath);

    // analyzePeDependencies 作用：
    // - 读取 PE Import Directory 并转换为依赖 DLL / 导入函数表；
    // - 支持 PE32 与 PE32+，损坏 PE 返回明确错误文本。
    // 参数 filePath：目标 EXE/DLL 或其它文件路径。
    // 返回：PeDependencyResult，UI 根据 success/isPe 决定显示表格或提示。
    PeDependencyResult analyzePeDependencies(const QString& filePath);
}
