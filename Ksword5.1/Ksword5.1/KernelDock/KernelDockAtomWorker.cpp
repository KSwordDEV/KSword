#include "KernelDockAtomWorker.h"

// ============================================================
// KernelDockAtomWorker.cpp
// 作用说明：
// 1) 遍历全局原子范围 [0xC000, 0xFFFF]；
// 2) 输出 GlobalGetAtomNameW / GetClipboardFormatNameW 可见条目；
// 3) 提供 GlobalFindAtomW 校验工具。
// ============================================================

#include "../Framework.h"

#include <algorithm> // std::sort：按 Atom 值排序。
#include <array>     // std::array：固定栈缓冲。
#include <vector>    // std::vector：结果容器。

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace
{
    // 原子范围常量：
    // - Windows 字符串原子通常位于 0xC000~0xFFFF。
    constexpr unsigned int kAtomStartValue = 0xC000U;
    constexpr unsigned int kAtomEndValue = 0xFFFFU;

    // formatAtomHexText：
    // - 作用：把原子值格式化为统一 0xXXXX 文本。
    QString formatAtomHexText(const std::uint16_t atomValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(atomValue), 4, 16, QChar('0'))
            .toUpper();
    }
}

bool runAtomTableSnapshotTask(std::vector<KernelAtomEntry>& rowsOut, QString& errorTextOut)
{
    rowsOut.clear();
    errorTextOut.clear();

    kLogEvent taskEvent;
    info << taskEvent << "[KernelDockAtomWorker] 开始遍历原子表。" << eol;

    std::vector<KernelAtomEntry> resultRows;
    resultRows.reserve(2048);

    for (unsigned int atomValueRaw = kAtomStartValue; atomValueRaw <= kAtomEndValue; ++atomValueRaw)
    {
        const ATOM atomValue = static_cast<ATOM>(atomValueRaw);

        std::array<wchar_t, 512> globalNameBuffer{};
        const UINT globalNameLength = ::GlobalGetAtomNameW(
            atomValue,
            globalNameBuffer.data(),
            static_cast<int>(globalNameBuffer.size()));

        std::array<wchar_t, 512> clipboardNameBuffer{};
        const int clipboardNameLength = ::GetClipboardFormatNameW(
            static_cast<UINT>(atomValue),
            clipboardNameBuffer.data(),
            static_cast<int>(clipboardNameBuffer.size()));

        if (globalNameLength == 0 && clipboardNameLength <= 0)
        {
            continue;
        }

        const QString globalNameText = globalNameLength > 0
            ? QString::fromWCharArray(globalNameBuffer.data(), static_cast<int>(globalNameLength)).trimmed()
            : QString();

        const QString clipboardNameText = clipboardNameLength > 0
            ? QString::fromWCharArray(clipboardNameBuffer.data(), clipboardNameLength).trimmed()
            : QString();

        KernelAtomEntry entry;
        entry.atomValue = static_cast<std::uint16_t>(atomValue);
        entry.atomNameText = !globalNameText.isEmpty() ? globalNameText : clipboardNameText;
        entry.statusText = QStringLiteral("SUCCESS");
        entry.querySucceeded = true;

        if (!globalNameText.isEmpty() && !clipboardNameText.isEmpty())
        {
            entry.sourceText = QStringLiteral("GlobalGetAtomNameW + GetClipboardFormatNameW");

        }
        else if (!globalNameText.isEmpty())
        {
            entry.sourceText = QStringLiteral("GlobalGetAtomNameW");

        }
        else
        {
            entry.sourceText = QStringLiteral("GetClipboardFormatNameW");

        }

        entry.detailDocument.section(QStringLiteral("原子来源"));
        if (!globalNameText.isEmpty()) entry.detailDocument.field(QStringLiteral("Global名称"), globalNameText);
        if (!clipboardNameText.isEmpty()) entry.detailDocument.field(QStringLiteral("ClipboardFormat名称"), clipboardNameText);
        if (!globalNameText.isEmpty() && !clipboardNameText.isEmpty())
            entry.detailDocument.field(QStringLiteral("名称一致"), QString::compare(globalNameText, clipboardNameText, Qt::CaseInsensitive) == 0 ? QStringLiteral("是") : QStringLiteral("否"), true);
        resultRows.push_back(std::move(entry));
    }

    std::sort(resultRows.begin(), resultRows.end(), [](const KernelAtomEntry& left, const KernelAtomEntry& right) {
        if (left.atomValue == right.atomValue)
        {
            return QString::compare(left.atomNameText, right.atomNameText, Qt::CaseInsensitive) < 0;
        }
        return left.atomValue < right.atomValue;
    });

    rowsOut = std::move(resultRows);

    info << taskEvent
        << "[KernelDockAtomWorker] 原子表遍历完成, count="
        << rowsOut.size()
        << eol;
    return true;
}

bool verifyGlobalAtomByName(
    const QString& atomNameText, std::uint16_t& atomValueOut, ks::ui::FieldDocument& document)
{
    atomValueOut = 0;
    document = ks::ui::FieldDocument{};
    document.section(QStringLiteral("原子名称校验"));
    const QString name = atomNameText.trimmed();
    document.field(QStringLiteral("名称"), name);
    if (name.isEmpty()) { document.note(QStringLiteral("校验失败：原子名称为空。")); return false; }
    const ATOM found = ::GlobalFindAtomW(reinterpret_cast<LPCWSTR>(name.utf16()));
    if (found == 0) { document.note(QStringLiteral("GlobalFindAtomW 未命中。")); return false; }
    atomValueOut = static_cast<std::uint16_t>(found);
    document.note(QStringLiteral("GlobalFindAtomW 命中。"));
    document.field(QStringLiteral("Atom值"), QString::number(atomValueOut));
    document.field(QStringLiteral("十六进制"), formatAtomHexText(atomValueOut));
    return true;
}
