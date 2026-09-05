#include "KvmControl.h"

#include "../Internationalization/LanguageManager.h"

#include <QSettings>
#include <QStringList>

#include <atomic>

namespace ksword::kvm
{
    namespace
    {
        // 写权限开关的持久化键。放在 Safety/ 下与其它安全门保持一致。
        const QString kWriteAccessSettingKey =
            QStringLiteral("Safety/Kvm/WriteAccessEnabled");

        // 进程内缓存：按钮刷新是高频路径，不能每次都读注册表。
        // -1 表示尚未从 QSettings 读入。
        std::atomic_int g_writeAccessCache{ -1 };

        // buildDetail：把一次快照压成 tooltip 用的多行说明。
        QString buildDetail(const KvmState& state)
        {
            QStringList lines;
            lines << ks::i18n::sourceText(QStringLiteral("KSwordVM（R-1 层）"));
            if (state.availability != KvmAvailability::Available &&
                !state.residentActive)
            {
                lines << describeAvailability(state.availability);
                return lines.join(QStringLiteral("\n"));
            }
            if (state.residentActive)
            {
                lines << ks::i18n::sourceText(
                    QStringLiteral("常驻中：%1/%2 个逻辑处理器在 VMX non-root"))
                    .arg(state.residentProcessorCount)
                    .arg(state.processorCount);
                lines << ks::i18n::sourceText(QStringLiteral("累计 VM-exit：%1"))
                    .arg(state.vmExitCount);
            }
            else
            {
                lines << ks::i18n::sourceText(
                    QStringLiteral("就绪：%1 个逻辑处理器已准备，未进入 non-root"))
                    .arg(state.processorCount);
            }
            // 常驻能不能活下来，取决于 MSR bitmap 与 exit 覆盖，这两项必须显式可见。
            lines << (state.msrBitmapReady
                ? ks::i18n::sourceText(QStringLiteral("MSR bitmap：可用"))
                : ks::i18n::sourceText(QStringLiteral("MSR bitmap：不可用（常驻会立即退出）")));
            lines << (state.sustainedProven
                ? ks::i18n::sourceText(QStringLiteral("常驻保持自检：已通过"))
                : ks::i18n::sourceText(QStringLiteral("常驻保持自检：未执行")));
            if (state.eptRuleCount > 0)
            {
                lines << ks::i18n::sourceText(QStringLiteral("EPT 规则：%1 条"))
                    .arg(state.eptRuleCount);
            }
            lines << (isWriteAccessEnabled()
                ? ks::i18n::sourceText(QStringLiteral("写权限：已开启（允许 R-1 改写）"))
                : ks::i18n::sourceText(QStringLiteral("写权限：已关闭（只读观测）")));
            if (state.faulted)
            {
                lines << ks::i18n::sourceText(
                    QStringLiteral("存在故障或待回滚，需要先重置"));
            }
            return lines.join(QStringLiteral("\n"));
        }

        // classify：把驱动返回的查询状态与状态位翻译成一个可用性结论。
        KvmAvailability classify(
            const ksword::ark::HvmStatusResult& result)
        {
            if (!result.io.ok || result.unsupported)
            {
                return KvmAvailability::DriverNotRunning;
            }
            switch (result.response.queryStatus)
            {
            case KSWORD_ARK_HVM_QUERY_STATUS_FIRMWARE_DISABLED:
                return KvmAvailability::FirmwareDisabled;
            case KSWORD_ARK_HVM_QUERY_STATUS_HYPERVISOR_CONFLICT:
                return KvmAvailability::HypervisorConflict;
            case KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU:
                return KvmAvailability::UnsupportedCpu;
            default:
                break;
            }
            if ((result.response.stateFlags &
                    (KSWORD_ARK_HVM_STATE_FAULTED |
                     KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED)) != 0UL)
            {
                return KvmAvailability::Faulted;
            }
            // 没有 MSR bitmap 就没有可存活的常驻，按不支持处理而不是"可用"。
            const unsigned long long requiredFeatures =
                KSWORD_ARK_HVM_FEATURE_INTEL |
                KSWORD_ARK_HVM_FEATURE_VMX |
                KSWORD_ARK_HVM_FEATURE_EPT |
                KSWORD_ARK_HVM_FEATURE_MSR_BITMAP |
                KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED;
            if ((result.response.featureFlags & requiredFeatures) !=
                requiredFeatures)
            {
                return KvmAvailability::UnsupportedCpu;
            }
            if ((result.response.stateFlags &
                    KSWORD_ARK_HVM_STATE_RESOURCES_READY) == 0UL)
            {
                return KvmAvailability::NotPrepared;
            }
            return KvmAvailability::Available;
        }

        // toCommandResult：把驱动控制结果翻译成 UI 可直接展示的结论。
        KvmCommandResult toCommandResult(
            const ksword::ark::HvmControlResult& result,
            const QString& actionName)
        {
            KvmCommandResult command;
            command.protocolStatus = result.response.status;
            command.ntStatus = result.response.lastStatus;
            command.ok = result.io.ok &&
                result.response.status == KSWORD_ARK_HVM_CONTROL_STATUS_OK;
            if (command.ok)
            {
                command.message = ks::i18n::sourceText(
                    QStringLiteral("%1 成功。")).arg(actionName);
                return command;
            }
            if (!result.io.ok && result.unsupported)
            {
                command.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：当前驱动不提供该能力。"))
                    .arg(actionName);
                return command;
            }
            QString reason;
            switch (result.response.status)
            {
            case KSWORD_ARK_HVM_CONTROL_STATUS_UNSUPPORTED_CPU:
                reason = ks::i18n::sourceText(QStringLiteral("处理器不支持"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_FIRMWARE_DISABLED:
                reason = ks::i18n::sourceText(QStringLiteral("固件已关闭虚拟化"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_HYPERVISOR_CONFLICT:
                reason = ks::i18n::sourceText(
                    QStringLiteral("已有 Hypervisor（Hyper-V/VBS）占用 VMX root"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_BUSY:
                reason = ks::i18n::sourceText(QStringLiteral("另一个 HVM 操作正在执行"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_RENDEZVOUS_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("全核集合失败"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_ROLLBACK_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral("需要先重置故障状态"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_POWER_TRANSITION_BLOCKED:
                reason = ks::i18n::sourceText(QStringLiteral("系统正在电源转换，已拒绝"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_NOT_PREPARED:
                reason = ks::i18n::sourceText(QStringLiteral("资源尚未准备"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_SELF_TEST_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("自检未通过"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_VERIFY_FAILED:
                reason = ks::i18n::sourceText(
                    QStringLiteral("状态代次已变化，请重新读取后再试"));
                break;
            default:
                reason = ks::i18n::sourceText(QStringLiteral("协议状态 %1"))
                    .arg(result.response.status);
                break;
            }
            command.message = ks::i18n::sourceText(QStringLiteral("%1 失败：%2。"))
                .arg(actionName)
                .arg(reason);
            return command;
        }
    }

    QString describeAvailability(const KvmAvailability availability)
    {
        switch (availability)
        {
        case KvmAvailability::Available:
            return ks::i18n::sourceText(QStringLiteral("可启动常驻"));
        case KvmAvailability::DriverNotRunning:
            return ks::i18n::sourceText(
                QStringLiteral("KswordARK 驱动未运行，请先启用 R0"));
        case KvmAvailability::UnsupportedCpu:
            return ks::i18n::sourceText(
                QStringLiteral("处理器不满足常驻硬件门（Intel VMX + EPT + MSR bitmap）"));
        case KvmAvailability::FirmwareDisabled:
            return ks::i18n::sourceText(
                QStringLiteral("固件中已关闭虚拟化，请在 BIOS/UEFI 中开启"));
        case KvmAvailability::HypervisorConflict:
            return ks::i18n::sourceText(
                QStringLiteral("Hyper-V/VBS 已占用 VMX root，需先关闭后重启"));
        case KvmAvailability::NotPrepared:
            return ks::i18n::sourceText(QStringLiteral("尚未准备资源，点击后自动准备"));
        case KvmAvailability::Faulted:
            return ks::i18n::sourceText(QStringLiteral("存在故障或待回滚，需要先重置"));
        }
        return QString();
    }

    KvmState queryState()
    {
        KvmState state;
        ksword::ark::DriverClient client;
        const auto result = client.queryHvmStatus();
        state.availability = classify(result);
        if (!result.io.ok || result.unsupported)
        {
            state.shortStatus = describeAvailability(state.availability);
            state.detail = buildDetail(state);
            return state;
        }

        const auto& response = result.response;
        state.generation = response.generation;
        state.processorCount = response.processorCount;
        state.residentProcessorCount = response.residentProcessorCount;
        state.eptRuleCount = response.eptRuleCount;
        state.vmExitCount = response.vmExitCount;
        state.residentActive = response.residentProcessorCount > 0UL ||
            (response.stateFlags &
                KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE) != 0UL;
        state.residentComplete = response.processorCount > 0UL &&
            response.residentProcessorCount == response.processorCount;
        state.faulted = (response.stateFlags &
            (KSWORD_ARK_HVM_STATE_FAULTED |
             KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED)) != 0UL;
        state.msrBitmapReady = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_MSR_BITMAP) != 0ULL;
        state.exitEmulationReady = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_EXIT_EMULATION) != 0ULL;
        state.sustainedProven = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_RESIDENT_SUSTAINED) != 0ULL;
        state.eptRulesReady = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_EPT_RULES) != 0ULL;

        if (state.residentActive)
        {
            state.shortStatus = state.residentComplete
                ? ks::i18n::sourceText(QStringLiteral("KVM 常驻中（全核）"))
                : ks::i18n::sourceText(QStringLiteral("KVM 常驻中（部分核心）"));
        }
        else
        {
            state.shortStatus = describeAvailability(state.availability);
        }
        state.detail = buildDetail(state);
        return state;
    }

    KvmCommandResult ensurePrepared()
    {
        ksword::ark::DriverClient client;
        const auto status = client.queryHvmStatus();
        if (!status.io.ok || status.unsupported)
        {
            KvmCommandResult failure;
            failure.message = describeAvailability(
                KvmAvailability::DriverNotRunning);
            return failure;
        }

        unsigned long generation = status.response.generation;
        // 资源已经就绪时不重复分配：PREPARE 对已就绪状态会返回 ALREADY_PREPARED。
        if ((status.response.stateFlags &
                KSWORD_ARK_HVM_STATE_RESOURCES_READY) == 0UL)
        {
            const auto prepared = client.controlHvm(
                KSWORD_ARK_HVM_CONTROL_PREPARE,
                generation,
                false,
                false,
                true);
            auto result = toCommandResult(
                prepared,
                ks::i18n::sourceText(QStringLiteral("准备 KVM 资源")));
            if (!result.ok)
            {
                return result;
            }
            generation = prepared.response.newGeneration;
        }
        // 自检证明每个逻辑处理器都能进出 VMX root，是常驻启动的前置条件。
        if ((status.response.stateFlags &
                KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED) == 0UL)
        {
            const auto tested = client.controlHvm(
                KSWORD_ARK_HVM_CONTROL_SELF_TEST,
                generation,
                true,
                false,
                true);
            return toCommandResult(
                tested,
                ks::i18n::sourceText(QStringLiteral("KVM 自检")));
        }

        KvmCommandResult success;
        success.ok = true;
        success.message = ks::i18n::sourceText(QStringLiteral("KVM 资源已就绪。"));
        return success;
    }

    KvmCommandResult startResident(const unsigned long expectedGeneration)
    {
        // 常驻启动前必须先准备并自检，否则驱动会直接拒绝。
        const auto prepared = ensurePrepared();
        if (!prepared.ok)
        {
            return prepared;
        }
        ksword::ark::DriverClient client;
        // 准备与自检都会推进代次，因此重新读取而不是沿用调用方传入的值。
        const auto refreshed = client.queryHvmStatus();
        const unsigned long generation = refreshed.io.ok
            ? refreshed.response.generation
            : expectedGeneration;
        const auto started = client.controlHvm(
            KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
            generation,
            true,
            false,
            true,
            true);
        return toCommandResult(
            started,
            ks::i18n::sourceText(QStringLiteral("启动 KVM 常驻")));
    }

    KvmCommandResult stopResident(const unsigned long expectedGeneration)
    {
        ksword::ark::DriverClient client;
        const auto stopped = client.controlHvm(
            KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
            expectedGeneration,
            false,
            false,
            true);
        return toCommandResult(
            stopped,
            ks::i18n::sourceText(QStringLiteral("停止 KVM 常驻")));
    }

    KvmCommandResult runSoak(
        const unsigned long expectedGeneration,
        const unsigned long milliseconds)
    {
        const auto prepared = ensurePrepared();
        if (!prepared.ok)
        {
            return prepared;
        }
        ksword::ark::DriverClient client;
        const auto refreshed = client.queryHvmStatus();
        const unsigned long generation = refreshed.io.ok
            ? refreshed.response.generation
            : expectedGeneration;
        const auto soaked = client.controlHvm(
            KSWORD_ARK_HVM_CONTROL_SOAK,
            generation,
            true,
            false,
            true,
            true,
            false,
            false,
            milliseconds);
        auto result = toCommandResult(
            soaked,
            ks::i18n::sourceText(QStringLiteral("KVM 常驻保持自检")));
        if (result.ok)
        {
            result.message = ks::i18n::sourceText(
                QStringLiteral("常驻保持自检通过：保持 %1 毫秒，无处理器掉出 non-root。"))
                .arg(soaked.response.soakElapsedMilliseconds);
        }
        else if (soaked.response.soakUnexpectedDevirtualizations > 0UL)
        {
            // 掉核是最有价值的失败证据，必须原样呈现而不是并入通用失败文案。
            result.message = ks::i18n::sourceText(
                QStringLiteral("常驻保持自检失败：保持 %1 毫秒后有 %2 个处理器掉出 non-root。"))
                .arg(soaked.response.soakElapsedMilliseconds)
                .arg(soaked.response.soakUnexpectedDevirtualizations);
        }
        return result;
    }

    KvmCommandResult resetFault(const unsigned long expectedGeneration)
    {
        ksword::ark::DriverClient client;
        const auto reset = client.controlHvm(
            KSWORD_ARK_HVM_CONTROL_RESET_FAULT,
            expectedGeneration,
            true,
            false,
            true);
        return toCommandResult(
            reset,
            ks::i18n::sourceText(QStringLiteral("重置 KVM 故障状态")));
    }

    bool isWriteAccessEnabled()
    {
        const int cached = g_writeAccessCache.load(std::memory_order_relaxed);
        if (cached >= 0)
        {
            return cached != 0;
        }
        QSettings settings;
        const bool enabled =
            settings.value(kWriteAccessSettingKey, false).toBool();
        g_writeAccessCache.store(enabled ? 1 : 0, std::memory_order_relaxed);
        return enabled;
    }

    void setWriteAccessEnabled(const bool enabled)
    {
        QSettings settings;
        settings.setValue(kWriteAccessSettingKey, enabled);
        g_writeAccessCache.store(enabled ? 1 : 0, std::memory_order_relaxed);
    }

    namespace
    {
        // toMemoryResult：把驱动响应翻译成 UI 可直接展示的结论。
        KvmMemoryResult toMemoryResult(
            const ksword::ark::HvmMemoryResult& result,
            const QString& actionName,
            const bool expectPayload)
        {
            KvmMemoryResult memory;
            memory.usedDirectWindow = result.response.usedDirectWindow != 0;
            memory.windowReady = result.response.windowReady != 0;
            memory.physicalAddress = result.response.physicalAddress;
            memory.ok = result.io.ok &&
                result.response.status == KSWORD_ARK_HVM_MEMORY_STATUS_OK;
            if (memory.ok)
            {
                if (expectPayload)
                {
                    memory.data = QByteArray(
                        reinterpret_cast<const char*>(result.response.data),
                        static_cast<int>(result.response.bytesTransferred));
                }
                memory.message = ks::i18n::sourceText(
                    QStringLiteral("%1 成功。")).arg(actionName);
                return memory;
            }
            if (!result.io.ok && result.unsupported)
            {
                memory.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：当前驱动不提供该能力。"))
                    .arg(actionName);
                return memory;
            }
            QString reason;
            switch (result.response.status)
            {
            case KSWORD_ARK_HVM_MEMORY_STATUS_CONFIRMATION_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral("需要显式确认"));
                break;
            case KSWORD_ARK_HVM_MEMORY_STATUS_WINDOW_UNAVAILABLE:
                reason = ks::i18n::sourceText(
                    QStringLiteral("私有页表窗口不可用"));
                break;
            case KSWORD_ARK_HVM_MEMORY_STATUS_ADDRESS_INVALID:
                reason = ks::i18n::sourceText(QStringLiteral("地址或长度非法"));
                break;
            case KSWORD_ARK_HVM_MEMORY_STATUS_TRANSLATION_FAILED:
                reason = ks::i18n::sourceText(
                    QStringLiteral("该地址在目标页表中未映射"));
                break;
            case KSWORD_ARK_HVM_MEMORY_STATUS_ACCESS_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("访问该物理页失败"));
                break;
            case KSWORD_ARK_HVM_MEMORY_STATUS_PARTIAL:
                reason = ks::i18n::sourceText(
                    QStringLiteral("只完成了 %1 字节"))
                    .arg(result.response.bytesTransferred);
                break;
            default:
                reason = ks::i18n::sourceText(QStringLiteral("协议状态 %1"))
                    .arg(result.response.status);
                break;
            }
            memory.message = ks::i18n::sourceText(QStringLiteral("%1 失败：%2。"))
                .arg(actionName)
                .arg(reason);
            return memory;
        }

        // denyWithoutWriteAccess：写权限关闭时统一拒绝，且不发起任何 IOCTL。
        KvmMemoryResult denyWithoutWriteAccess(const QString& actionName)
        {
            KvmMemoryResult memory;
            memory.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：R-1 写权限未开启。"))
                .arg(actionName);
            return memory;
        }
    }

    KvmMemoryResult queryMemoryWindow()
    {
        ksword::ark::DriverClient client;
        // 窗口查询不触碰内存，因此不需要确认令牌之外的任何门。
        const auto result = client.hvmMemory(
            KSWORD_ARK_HVM_MEMORY_OP_QUERY_WINDOW,
            0,
            0,
            0,
            nullptr,
            false,
            true);
        return toMemoryResult(
            result,
            ks::i18n::sourceText(QStringLiteral("查询 R-1 内存窗口")),
            false);
    }

    KvmMemoryResult readPhysical(
        const unsigned long long physicalAddress,
        const unsigned long length)
    {
        ksword::ark::DriverClient client;
        const auto result = client.hvmMemory(
            KSWORD_ARK_HVM_MEMORY_OP_READ_PHYSICAL,
            physicalAddress,
            0,
            length,
            nullptr,
            false,
            true);
        return toMemoryResult(
            result,
            ks::i18n::sourceText(QStringLiteral("R-1 读取物理内存")),
            true);
    }

    KvmMemoryResult writePhysical(
        const unsigned long long physicalAddress,
        const QByteArray& payload)
    {
        const QString actionName =
            ks::i18n::sourceText(QStringLiteral("R-1 写入物理内存"));
        // 写权限是进程内的第二道门：关闭时连 IOCTL 都不发。
        if (!isWriteAccessEnabled())
        {
            return denyWithoutWriteAccess(actionName);
        }
        ksword::ark::DriverClient client;
        const auto result = client.hvmMemory(
            KSWORD_ARK_HVM_MEMORY_OP_WRITE_PHYSICAL,
            physicalAddress,
            0,
            static_cast<unsigned long>(payload.size()),
            reinterpret_cast<const unsigned char*>(payload.constData()),
            // 写只能走私有窗口，MmCopyMemory 没有物理写路径，
            // 与其让驱动在回退路径上失败，不如直接要求窗口。
            true,
            true);
        return toMemoryResult(result, actionName, false);
    }

    KvmMemoryResult readVirtual(
        const unsigned long long directoryBase,
        const unsigned long long virtualAddress,
        const unsigned long length)
    {
        ksword::ark::DriverClient client;
        const auto result = client.hvmMemory(
            KSWORD_ARK_HVM_MEMORY_OP_READ_VIRTUAL,
            virtualAddress,
            directoryBase,
            length,
            nullptr,
            false,
            true);
        return toMemoryResult(
            result,
            ks::i18n::sourceText(QStringLiteral("R-1 读取虚拟内存")),
            true);
    }

    KvmMemoryResult writeVirtual(
        const unsigned long long directoryBase,
        const unsigned long long virtualAddress,
        const QByteArray& payload)
    {
        const QString actionName =
            ks::i18n::sourceText(QStringLiteral("R-1 写入虚拟内存"));
        if (!isWriteAccessEnabled())
        {
            return denyWithoutWriteAccess(actionName);
        }
        ksword::ark::DriverClient client;
        const auto result = client.hvmMemory(
            KSWORD_ARK_HVM_MEMORY_OP_WRITE_VIRTUAL,
            virtualAddress,
            directoryBase,
            static_cast<unsigned long>(payload.size()),
            reinterpret_cast<const unsigned char*>(payload.constData()),
            true,
            true);
        return toMemoryResult(result, actionName, false);
    }

    KvmMemoryResult translate(
        const unsigned long long directoryBase,
        const unsigned long long virtualAddress)
    {
        ksword::ark::DriverClient client;
        const auto result = client.hvmMemory(
            KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE,
            virtualAddress,
            directoryBase,
            0,
            nullptr,
            false,
            true);
        return toMemoryResult(
            result,
            ks::i18n::sourceText(QStringLiteral("R-1 地址翻译")),
            false);
    }

    namespace
    {
        // toViewResult：把驱动视图响应翻译成 UI 可直接展示的结论。
        KvmViewResult toViewResult(
            const ksword::ark::HvmViewResult& result,
            const QString& actionName)
        {
            KvmViewResult view;
            view.viewId = result.response.viewId;
            view.viewCount = result.response.viewCount;
            view.ok = result.io.ok &&
                result.response.status == KSWORD_ARK_HVM_VIEW_STATUS_OK;
            if (view.ok)
            {
                const unsigned long rows =
                    result.response.returnedRows <= KSWORD_ARK_HVM_MAX_VIEWS
                        ? result.response.returnedRows
                        : KSWORD_ARK_HVM_MAX_VIEWS;
                for (unsigned long index = 0; index < rows; ++index)
                {
                    const auto& row = result.response.rows[index];
                    KvmViewEntry entry;
                    entry.viewId = row.viewId;
                    entry.kind = row.kind;
                    entry.flags = row.flags;
                    entry.physicalAddress = row.physicalAddress;
                    entry.shadowPhysicalAddress = row.shadowPhysicalAddress;
                    entry.flipCount = row.flipCount;
                    view.views.append(entry);
                }
                view.message = ks::i18n::sourceText(
                    QStringLiteral("%1 成功。")).arg(actionName);
                return view;
            }
            if (!result.io.ok && result.unsupported)
            {
                view.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：当前驱动不提供该能力。"))
                    .arg(actionName);
                return view;
            }
            QString reason;
            switch (result.response.status)
            {
            case KSWORD_ARK_HVM_VIEW_STATUS_CONFIRMATION_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral("需要显式确认"));
                break;
            case KSWORD_ARK_HVM_VIEW_STATUS_NOT_PREPARED:
                reason = ks::i18n::sourceText(QStringLiteral("资源尚未准备"));
                break;
            case KSWORD_ARK_HVM_VIEW_STATUS_NOT_FOUND:
                reason = ks::i18n::sourceText(QStringLiteral("没有这条视图"));
                break;
            case KSWORD_ARK_HVM_VIEW_STATUS_TABLE_FULL:
                reason = ks::i18n::sourceText(QStringLiteral("视图表已满"));
                break;
            case KSWORD_ARK_HVM_VIEW_STATUS_SPLIT_FAILED:
                reason = ks::i18n::sourceText(
                    QStringLiteral("无法把该页拆成四 KiB 粒度"));
                break;
            case KSWORD_ARK_HVM_VIEW_STATUS_LEAF_CONFLICT:
                reason = ks::i18n::sourceText(
                    QStringLiteral("该页已被另一条视图或 EPT 规则占用"));
                break;
            case KSWORD_ARK_HVM_VIEW_STATUS_EXECUTE_ONLY_UNSUPPORTED:
                reason = ks::i18n::sourceText(
                    QStringLiteral("处理器不支持仅执行的 EPT 叶项，无法隐藏"));
                break;
            case KSWORD_ARK_HVM_VIEW_STATUS_MULTIPROCESSOR_UNSAFE:
                reason = ks::i18n::sourceText(
                    QStringLiteral("视图翻转共享叶项，只能在单处理器且未常驻时安装"));
                break;
            case KSWORD_ARK_HVM_VIEW_STATUS_RESOURCE_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("影子页分配或捕获失败"));
                break;
            default:
                reason = ks::i18n::sourceText(QStringLiteral("协议状态 %1"))
                    .arg(result.response.status);
                break;
            }
            view.message = ks::i18n::sourceText(QStringLiteral("%1 失败：%2。"))
                .arg(actionName)
                .arg(reason);
            return view;
        }

        // denyViewWithoutWriteAccess：写权限关闭时统一拒绝，不发起 IOCTL。
        KvmViewResult denyViewWithoutWriteAccess(const QString& actionName)
        {
            KvmViewResult view;
            view.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：R-1 写权限未开启。"))
                .arg(actionName);
            return view;
        }
    }

    KvmViewResult listViews()
    {
        ksword::ark::DriverClient client;
        const auto result = client.controlHvmView(
            KSWORD_ARK_HVM_VIEW_OP_QUERY,
            0, 0, 0, 0, nullptr, false, false, false, false);
        return toViewResult(
            result,
            ks::i18n::sourceText(QStringLiteral("读取 EPT 视图")));
    }

    KvmViewResult addView(
        const unsigned long kind,
        const unsigned long long physicalAddress,
        const KvmViewShadowSeed seed,
        const QByteArray& shadow)
    {
        const QString actionName =
            ks::i18n::sourceText(QStringLiteral("安装 EPT 视图"));
        if (!isWriteAccessEnabled())
        {
            return denyViewWithoutWriteAccess(actionName);
        }
        // 显式影子内容必须恰好一页：驱动按整页拷贝，短了会读到未初始化数据。
        QByteArray page;
        if (seed == KvmViewShadowSeed::Explicit)
        {
            if (shadow.size() != static_cast<int>(KSWORD_ARK_HVM_VIEW_PAGE_BYTES))
            {
                KvmViewResult view;
                view.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：影子内容必须正好是 %2 字节。"))
                    .arg(actionName)
                    .arg(static_cast<int>(KSWORD_ARK_HVM_VIEW_PAGE_BYTES));
                return view;
            }
            page = shadow;
        }
        ksword::ark::DriverClient client;
        const auto result = client.controlHvmView(
            KSWORD_ARK_HVM_VIEW_OP_ADD,
            kind,
            0,
            0,
            physicalAddress,
            page.isEmpty()
                ? nullptr
                : reinterpret_cast<const unsigned char*>(page.constData()),
            seed == KvmViewShadowSeed::FromTarget,
            seed == KvmViewShadowSeed::Zero,
            true,
            true);
        return toViewResult(result, actionName);
    }

    KvmViewResult removeView(const unsigned long viewId)
    {
        const QString actionName =
            ks::i18n::sourceText(QStringLiteral("移除 EPT 视图"));
        if (!isWriteAccessEnabled())
        {
            return denyViewWithoutWriteAccess(actionName);
        }
        ksword::ark::DriverClient client;
        const auto result = client.controlHvmView(
            KSWORD_ARK_HVM_VIEW_OP_REMOVE,
            0, viewId, 0, 0, nullptr, false, false, false, true);
        return toViewResult(result, actionName);
    }

    KvmViewResult clearViews()
    {
        const QString actionName =
            ks::i18n::sourceText(QStringLiteral("清空 EPT 视图"));
        if (!isWriteAccessEnabled())
        {
            return denyViewWithoutWriteAccess(actionName);
        }
        ksword::ark::DriverClient client;
        const auto result = client.controlHvmView(
            KSWORD_ARK_HVM_VIEW_OP_CLEAR,
            0, 0, 0, 0, nullptr, false, false, false, true);
        return toViewResult(result, actionName);
    }
}
