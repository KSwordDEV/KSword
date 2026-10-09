#pragma once

#include "RegistryDocumentApply.h"
#include "RegistryWorkbenchAccess.h"

// 注册表工作台共用事务适配器：构造时固定真实通道/视图，全部调用保留原始值名和数据。
// 此适配器不宣称多次普通读写具有跨进程原子性；状态机在每步复核并记录实际回执。
class RegistryAccessApplyBackend final : public RegistryApplyBackend
{
public:
    // context 是用户启动动作时捕获的来源；调用期间永不从 UI 重选。
    explicit RegistryAccessApplyBackend(const RegistryAccessContext& context);
    bool keyExists(const QString& path, bool& exists, QString& error) override;
    bool readValue(const QString& path, const QString& name,
        RegistryApplyValueState& value, QString& error) override;
    bool captureTree(const QString& path, RegistryDocument& tree, QString& error) override;
    bool captureTreeBounded(const QString& path, qint64 maximumDataBytes,
        RegistryDocument& tree, QString& error) override;
    bool createKey(const QString& path, QString& error) override;
    bool setValue(const QString& path, const QString& name, quint32 type,
        const QByteArray& data, QString& error) override;
    bool deleteValue(const QString& path, const QString& name, QString& error) override;
    bool deleteTree(const QString& path, const RegistryDocument& expectedTree, QString& error) override;

private:
    RegistryAccessContext m_context; // 固定访问上下文，与预览和实际来源一致。
};
