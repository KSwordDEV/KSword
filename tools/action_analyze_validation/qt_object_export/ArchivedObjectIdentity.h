#pragma once

#include "../../../Ksword5.1/Ksword5.1/ActionAnalyze/ObjectDiagnosticExport.h"

#include <QByteArrayView>

namespace ks::action_analyze
{
    enum class ArchivedObjectKind { Process, Thread };

    enum class ArchivedIdentityState
    {
        Ready,           // 对应已核验的对象与归属，结果含菜单身份。
        Missing,         // 上游未取得对象正文。
        Unresolved,      // 对象为弱引用、缺少强 owner 或超出当前菜单支持的实例范围。
        Invalid,         // 正文或所需的身份字段不符合 A0。
        IdentityMismatch // 项目上下文中的对象、采样、类别或引用关系不同。
    };

    struct ArchivedIdentityResult
    {
        ArchivedIdentityState state = ArchivedIdentityState::Invalid; // 只读解析及匹配结果。
        std::optional<ObjectSelection> subject; // 仅 Ready 携带可使用的对象与所属进程。
    };

    // 解析 identity.schema.json 的进程／线程值。输入项目身份和正文从归档所有者的已验证采样读取，
    // 正文中的 verification 只是已记录字段，采样来源和已提交记录的可信性由调用者负责。
    // 函数只借用本轮字节，不扫描项目目录，也不解码 Stored 记录封装。
    ArchivedIdentityResult ResolveArchivedObjectIdentity(const ObjectSampleRef& sample, ArchivedObjectKind kind,
        quint64 objectId, std::optional<QByteArrayView> observation,
        std::optional<QByteArrayView> ownerObservation = std::nullopt);
}
