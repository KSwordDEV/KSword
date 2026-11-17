#pragma once
#include "ArkDriverTypes.h"
#include <QString>
#include <functional>
namespace ksword::ark
{
    // LocalPdbProfile：
    // - 作用：保存一个本地 JSON profile 解析结果；
    // - 输入来源：profiles/ark_dyndata/*.json；
    // - 返回行为：作为 DriverClient::applyDynDataProfile 的输入，不持有 PDB 文件。
    struct LocalPdbProfile
    {
        bool valid = false;                              // valid：R3 语法和范围校验是否通过。
        bool matched = false;                            // matched：module identity 是否精确匹配当前 ntoskrnl。
        std::uint32_t ignoredUnknownFields = 0;          // ignoredUnknownFields：JSON 中 R3 不认识的字段数。
        QString sourceText;                              // sourceText：profile 来源，区分 pack 与散落 JSON。
        QString pathText;                                // pathText：profile 文件路径。
        QString diagnosticsText;                         // diagnosticsText：解析/校验诊断。
        ksword::ark::DynDataProfileApplyInput applyInput; // applyInput：可直接打包给 R0 的 v1 profile。
        ksword::ark::DynDataProfileApplyExInput applyExInput; // applyExInput：可直接打包给 R0 的 v2/v3 typed-item profile。
        ksword::ark::DynDataV4ApplyInput applyV4Input;    // applyV4Input：可直接发送给 R0 v4 存储层的稳定 item profile。
        std::uint32_t exAppliedCount = 0;               // exAppliedCount：v2/v3 typed items 数量。
        std::uint32_t callbackItemCount = 0;            // callbackItemCount：原始 callbackItems 条目数。
        std::uint32_t typedItemCount = 0;               // typedItemCount：v3 items/typedItems 条目数。
        std::uint32_t v4ItemCount = 0;                  // v4ItemCount：v4 stable item 数量。
    };


    using DynDataProfileText = std::function<QString(const char*, const QString&)>;
    LocalPdbProfile findMatchingPdbProfile(const ArkDynModuleIdentity& identity,
        QString& diagnostics, const DynDataProfileText& texts = {});
}
