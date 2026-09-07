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

        // 嵌套模式开关的持久化键。
        const QString kNestedAllowedSettingKey =
            QStringLiteral("Safety/Kvm/NestedAllowed");
        // 私有 EPT 与 #VE / VMFUNC 不同：它不放开能力，只是让已有能力在多核
        // 上安全。所以它持久化，和嵌套模式一样。
        const QString kLocalEptSettingKey =
            QStringLiteral("Safety/Kvm/LocalEptEnabled");
        std::atomic<int> g_localEptCache{ -1 };
        // 后端选择同样不放开能力，只是换一套装视图的机器，所以也持久化。
        const QString kEptpSwitchSettingKey =
            QStringLiteral("Safety/Kvm/EptpSwitchEnabled");
        std::atomic<int> g_eptpSwitchCache{ -1 };
        // #VE 只活在本进程里，没有对应的设置键，这样它无法跨会话残留。
        std::atomic<bool> g_veEnabled{ false };
        // VMFUNC 同样不落设置键：武装一个 guest 可见的接口不该跨会话残留。
        std::atomic<bool> g_vmFuncEnabled{ false };

        // 进程内缓存：按钮刷新是高频路径，不能每次都读注册表。
        // -1 表示尚未从 QSettings 读入。
        std::atomic_int g_writeAccessCache{ -1 };
        std::atomic_int g_nestedAllowedCache{ -1 };

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
            // 装分离视图的后端有两套，且必须按【武装位】而不是按请求显示。
            // 请求了却因为能力不够没武装上时，驱动保持默认后端并且不报错，
            // 这时显示成"已开启"比直接报错更糟：调用方会拿一个假前提去推理
            // 跨处理器可见性。所以三种情形各说各的，不合并。
            if (state.eptpSwitchArmed)
            {
                lines << ks::i18n::sourceText(QStringLiteral("分离视图后端：EPTP 切换（已武装，不需要 Monitor Trap Flag）"));
            }
            else if (isEptpSwitchEnabled())
            {
                lines << ks::i18n::sourceText(QStringLiteral("分离视图后端：写叶 + Monitor Trap Flag。已请求 EPTP 切换但未武装——驱动没有确认它需要的能力（INVEPT single 与 execute-only EPT 叶），或者资源是在打开这个开关之前准备的"));
            }
            else
            {
                lines << ks::i18n::sourceText(QStringLiteral("分离视图后端：写叶 + Monitor Trap Flag（默认）"));
            }
            // 每处理器私有 EPT 与上面的后端选择是同一个模式：菜单上的勾是
            // **请求**，只有武装位才是事实。多核上装视图恰恰依赖它，而请求了
            // 没武装时启动常驻只会回一个裸状态码 21，用户无从知道差在哪。
            if (state.localEptArmed)
            {
                lines << ks::i18n::sourceText(QStringLiteral("每处理器私有 EPT：已武装（多核上可以安装分离视图）"));
            }
            else if (isLocalEptEnabled())
            {
                lines << ks::i18n::sourceText(QStringLiteral("每处理器私有 EPT：**已请求但未武装** —— 驱动没有确认它需要的能力（INVEPT single 与 Monitor Trap Flag），或者资源是在打开这个开关之前准备的。多核上安装分离视图会被拒"));
            }
            else if (state.processorCount > 1UL)
            {
                lines << ks::i18n::sourceText(QStringLiteral("每处理器私有 EPT：未请求。这台机器是多核，分离视图在共享层次上不安全，会被拒绝安装"));
            }
            // 两个危险开关必须在状态里可见，而不是只在菜单勾选框里。
            // 武装了却看不见，等于没有武装的自觉。
            if (state.veArmed)
            {
                lines << ks::i18n::sourceText(QStringLiteral("#VE：控制位已武装。仍有两道保险挡着实际投递（全叶项 suppress-#VE、信息区锁 busy）"));
            }
            if (state.vmFuncArmed)
            {
                lines << ks::i18n::sourceText(QStringLiteral("VMFUNC：已武装。guest 中任意 ring 3 线程都能切换 EPT 视图，且不产生 VM-exit"));
            }
            if (state.nestedResident)
            {
                lines << ks::i18n::sourceText(
                    QStringLiteral("嵌套运行：作为 L1 跑在外层 hypervisor 之下，性能与可用能力均降级"));
            }
            else if (state.hypervisorPresent)
            {
                lines << (isNestedAllowed()
                    ? ks::i18n::sourceText(QStringLiteral("嵌套模式：已开启"))
                    : ks::i18n::sourceText(QStringLiteral("嵌套模式：已关闭（外层有 hypervisor，常驻会被拒绝）")));
            }
            // 出站方向：谁想跑在我们之下。
            //
            // 这一行只在非零时出现，因为它平时恒为零，而它非零时说的是一件用户在
            // 别处看不出因果的事：机器上的另一个 hypervisor 起不了虚拟机，是我们挡的。
            // 驱动侧那个瞬时状态位在 VMXOFF 就被清掉，所以这里读的是只增不减的计数。
            if (state.nestedL2LaunchRefusedCount > 0UL)
            {
                lines << ks::i18n::sourceText(QStringLiteral("已拒绝 %1 次「在我们之下启动虚拟机」的请求：本机另一个 hypervisor（VMware / VirtualBox / WSL2 / Docker 等）尝试过 VMLAUNCH 并被拒。我们不提供嵌套 VMX，所以它的虚拟机在我们常驻期间起不来 —— 用户那边看到的现象是「虚拟机突然起不来了」，而线索不会指向这里。"))
                    .arg(state.nestedL2LaunchRefusedCount);
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
            case KSWORD_ARK_HVM_QUERY_STATUS_BACKEND_NOT_IMPLEMENTED:
                return KvmAvailability::BackendNotImplemented;
            default:
                break;
            }
            if ((result.response.stateFlags &
                    (KSWORD_ARK_HVM_STATE_FAULTED |
                     KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED)) != 0UL)
            {
                return KvmAvailability::Faulted;
            }
            // 外层有 hypervisor 而嵌套模式没开：驱动会拒绝常驻，但这是用户
            // 一个开关就能解决的，报成"不支持"会让人以为得换机器。
            if ((result.response.featureFlags &
                    KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL &&
                !isNestedAllowed())
            {
                return KvmAvailability::NestedNotAllowed;
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
                reason = ks::i18n::sourceText(QStringLiteral("资源尚未准备。先在 KVM 菜单里执行「准备资源」"));
                break;
            // ---- 以下这一批以前全部落进 default，只给用户一个裸数字 ----
            //
            // 撞得最多的是 LOCAL_EPT 那七个（21-27）：它们是「每处理器私有 EPT」
            // 开关的必经之路，而那个开关又是多核上安装分离视图的唯一途径。
            // 用户看到的只有「协议状态 21」，既不知道 21 是什么，也不知道
            // 下一步该做什么。
            case KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST:
                reason = ks::i18n::sourceText(QStringLiteral("请求本身不合法：多半是同时请求了互斥的能力，或带了这条命令不接受的标志"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_CONFIRMATION_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral("缺少显式确认位。这与安全策略无关，是协议要求调用方明确表态"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_ALREADY_PREPARED:
                reason = ks::i18n::sourceText(QStringLiteral("资源已经准备过了。重复准备会把状态打成 FAULTED，所以驱动直接拒绝；要换配置请先「释放资源」"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_RESOURCE_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("分配每处理器资源失败（多半是非分页内存不足）"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_GUEST_LAUNCH_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("一次性受控来宾没能启动：VMCS 构造或 VMLAUNCH 被拒"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_UNEXPECTED_VMEXIT:
                reason = ks::i18n::sourceText(QStringLiteral("来宾产生了未预期的 VM 退出，已按 fail-closed 处理"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_PARTIAL_IMPLEMENTATION:
                reason = ks::i18n::sourceText(QStringLiteral("这条路径只有部分实现，驱动拒绝在半成品上继续"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_NESTED_UNSUPPORTED:
                reason = ks::i18n::sourceText(QStringLiteral("外层 hypervisor 没有向本机暴露嵌套 VMX"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_EVMCS_UNSUPPORTED:
                reason = ks::i18n::sourceText(QStringLiteral("外层 hypervisor 不提供 eVMCS"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_LIFECYCLE_GUARD_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("生命周期守卫拒绝：常驻已在跑，或电源/拓扑/卸载守卫没有全部就位"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_NOT_ARMED:
                reason = ks::i18n::sourceText(QStringLiteral("请求了每处理器私有 EPT，但它没有被武装。武装发生在**准备资源**那一步，所以打开开关之后必须先「释放资源」再重新准备"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_LEAF_SET_TOO_LARGE:
                reason = ks::i18n::sourceText(QStringLiteral("要镜像的可翻转叶太多，超出每处理器私有层次的上限。先移除一些视图或规则"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_PAGE_BUDGET_EXHAUSTED:
                reason = ks::i18n::sourceText(QStringLiteral("私有 EPT 层次的页预算不够。处理器越多每叶越贵，减少视图/规则数量或减少核数"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_SPLIT_MISSING:
                reason = ks::i18n::sourceText(QStringLiteral("某一页缺少 4KiB 分裂，私有层次无法镜像它。这通常意味着规则或视图表在准备之后被改过"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_VERIFY_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("私有 EPT 层次建好之后没有通过自校验，已拒绝使用（宁可不启动，也不在没验过的页表上跑）"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_CONFLICTS_WITH_VMFUNC:
                reason = ks::i18n::sourceText(QStringLiteral("私有 EPT 与 VMFUNC 互斥：VMFUNC 发布一份全处理器共用的 EPTP 列表，而私有层次让同一个索引在每个处理器上指向不同的东西"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_CONFLICTS_WITH_NESTED:
                reason = ks::i18n::sourceText(QStringLiteral("私有 EPT 与嵌套 VMX 互斥。请关掉其中一个"));
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
        case KvmAvailability::BackendNotImplemented:
            return ks::i18n::sourceText(
                QStringLiteral("处理器支持 AMD SVM，但本版本尚未实现 SVM 后端"));
        case KvmAvailability::NestedNotAllowed:
            return ks::i18n::sourceText(
                QStringLiteral("检测到外层 hypervisor（虚拟机或 VBS/HVCI）。在右键菜单中开启嵌套模式后可以作为 L1 运行"));
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
        state.eptPointer = response.eptPointer;
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
        state.hypervisorPresent = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL;
        state.nestedResident = (response.stateFlags &
            KSWORD_ARK_HVM_STATE_RESIDENT_NESTED) != 0UL;
        state.nestedL2LaunchRefusedCount =
            response.nestedL2LaunchRefusedCount;
        state.veArmed = (response.stateFlags &
            KSWORD_ARK_HVM_STATE_VE_ACTIVE) != 0UL;
        state.veSuppressedByDefault = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_VE_SUPPRESSED_BY_DEFAULT) != 0ULL;
        state.vmFuncArmed = (response.stateFlags &
            KSWORD_ARK_HVM_STATE_VMFUNC_ACTIVE) != 0UL;
        state.eptpSwitchingAvailable = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_EPTP_SWITCHING) != 0ULL;
        // 读武装位而不是读本地请求开关：驱动只在能力齐备时才置这一位，
        // 缺能力时它保持默认后端而不报错，请求位在两种情形下完全一样。
        state.eptpSwitchArmed = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED) != 0ULL;
        // 同一条理由，同一个坑：私有 EPT 以前只在菜单勾选框里可见，
        // 而那是**请求**。驱动能力不够时保持共享层次且不报错。
        state.localEptArmed = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED) != 0ULL;
        // 视图安装前置：驱动一条一条查，UI 也得能一条一条报。以前这四位没上来，
        // 于是「装不上」只能显示成一个协议状态码，用户看不出缺的是哪一条。
        state.resourcesReady = (response.stateFlags &
            KSWORD_ARK_HVM_STATE_RESOURCES_READY) != 0UL;
        state.eptReady = (response.stateFlags &
            KSWORD_ARK_HVM_STATE_EPT_READY) != 0UL;
        state.inveptSingleReady = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE) != 0ULL;
        state.monitorTrapFlagReady = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG) != 0ULL;

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
            // 后端选择只有 PREPARE 会读：驱动在准备资源时就决定武装与否，
            // 而 START_RESIDENT 的白名单会把这一位判成 INVALID_REQUEST。
            const auto prepared = client.controlHvm(
                KSWORD_ARK_HVM_CONTROL_PREPARE,
                generation,
                false,
                isNestedAllowed(),
                true,
                false,
                false,
                false,
                false,
                false,
                false,
                isEptpSwitchEnabled());
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
                isNestedAllowed(),
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
            isNestedAllowed(),
            true,
            true,
            false,
            false,
            isVeEnabled(),
            isVmFuncEnabled(),
            isLocalEptEnabled());
        // enableEptpSwitch 刻意留在默认的 false：后端在上面的 ensurePrepared
        // 里就随 PREPARE 定下来了，这一位出现在 START_RESIDENT 上会被驱动的
        // 白名单判成 INVALID_REQUEST。
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
            isNestedAllowed(),
            true,
            true,
            false,
            false,
            // enableVe：保持自检从不打开 #VE，它要证明的是常驻能活下来。
            false,
            // enableVmFunc：同理，保持自检不武装任何 guest 可见的切换接口。
            false,
            // enableLocalEpt：保持自检要证明的是常驻能活下来，不是私有层次
            // 能建起来，多建一套只会把失败原因混在一起。
            false,
            // enableEptpSwitch：这一位只有 PREPARE 认，SOAK 带上会被驳回；
            // 而且后端选的是怎么装视图，与常驻能不能活下来无关。
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

    KvmCommandResult releaseResources(const unsigned long expectedGeneration)
    {
        ksword::ark::DriverClient client;
        const auto released = client.controlHvm(
            KSWORD_ARK_HVM_CONTROL_TEARDOWN,
            expectedGeneration,
            true,
            false,
            true);
        return toCommandResult(
            released,
            ks::i18n::sourceText(QStringLiteral("释放 KVM 资源")));
    }

    bool isNestedAllowed()
    {
        const int cached = g_nestedAllowedCache.load(std::memory_order_relaxed);
        if (cached >= 0)
        {
            return cached != 0;
        }
        QSettings settings;
        const bool allowed =
            settings.value(kNestedAllowedSettingKey, false).toBool();
        g_nestedAllowedCache.store(allowed ? 1 : 0, std::memory_order_relaxed);
        return allowed;
    }

    void setNestedAllowed(const bool allowed)
    {
        QSettings settings;
        settings.setValue(kNestedAllowedSettingKey, allowed);
        g_nestedAllowedCache.store(allowed ? 1 : 0, std::memory_order_relaxed);
    }

    bool isVeEnabled()
    {
        // 进程内状态，刻意不落 QSettings：重启客户端即回到关闭。
        return g_veEnabled.load(std::memory_order_relaxed);
    }

    void setVeEnabled(const bool enabled)
    {
        g_veEnabled.store(enabled, std::memory_order_relaxed);
    }

    bool isLocalEptEnabled()
    {
        const int cached = g_localEptCache.load(std::memory_order_relaxed);
        if (cached >= 0)
        {
            return cached != 0;
        }
        QSettings settings;
        const bool enabled =
            settings.value(kLocalEptSettingKey, false).toBool();
        g_localEptCache.store(enabled ? 1 : 0, std::memory_order_relaxed);
        return enabled;
    }

    void setLocalEptEnabled(const bool enabled)
    {
        QSettings settings;
        settings.setValue(kLocalEptSettingKey, enabled);
        g_localEptCache.store(enabled ? 1 : 0, std::memory_order_relaxed);
    }

    bool isEptpSwitchEnabled()
    {
        const int cached = g_eptpSwitchCache.load(std::memory_order_relaxed);
        if (cached >= 0)
        {
            return cached != 0;
        }
        QSettings settings;
        const bool enabled =
            settings.value(kEptpSwitchSettingKey, false).toBool();
        g_eptpSwitchCache.store(enabled ? 1 : 0, std::memory_order_relaxed);
        return enabled;
    }

    void setEptpSwitchEnabled(const bool enabled)
    {
        QSettings settings;
        settings.setValue(kEptpSwitchSettingKey, enabled);
        g_eptpSwitchCache.store(enabled ? 1 : 0, std::memory_order_relaxed);
    }

    bool isVmFuncEnabled()
    {
        // 与 #VE 一样只活在本进程里：重启客户端即回到关闭。
        return g_vmFuncEnabled.load(std::memory_order_relaxed);
    }

    void setVmFuncEnabled(const bool enabled)
    {
        g_vmFuncEnabled.store(enabled, std::memory_order_relaxed);
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
        // 视图路径会回传的两个 NTSTATUS。就地给出数值而不是拉进 ntstatus.h：
        // 这一层只需要把两条分支分开，不需要整张状态码表。
        // 数值出处 Windows SDK 的 shared/ntstatus.h：
        // STATUS_DEVICE_BUSY = 0x80000011，STATUS_NOT_SUPPORTED = 0xC00000BB。
        constexpr long kViewStatusDeviceBusy =
            static_cast<long>(0x80000011UL);
        constexpr long kViewStatusNotSupported =
            static_cast<long>(0xC00000BBUL);

        // toViewResult：把驱动视图响应翻译成 UI 可直接展示的结论。
        KvmViewResult toViewResult(
            const ksword::ark::HvmViewResult& result,
            const QString& actionName)
        {
            KvmViewResult view;
            view.viewId = result.response.viewId;
            view.viewCount = result.response.viewCount;
            // 两级失败码在任何一条返回路径上都要带出去：调用方要靠它们定位
            // 失败发生在哪一步，而 message 一旦成句就丢掉了这个信息。
            view.protocolStatus = result.response.status;
            view.lastStatus = result.response.lastStatus;
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
            case KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST:
                // 以前这一条落进 default，显示成没有含义的「协议状态 1」。
                // 驱动把四种校验都归到这个码上，所以文案要把四种一起说出来，
                // 否则用户只能靠猜来分辨是地址写错了还是版本对不上。
                reason = ks::i18n::sourceText(
                    QStringLiteral("请求被判为无效：目标物理地址未按四 KiB 页对齐、或超出驱动映射上界八 TiB、或协议版本与结构大小与驱动不符、或指定的代次与当前代次不一致"));
                break;
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
                // 同一个协议码由两类完全不同的分支产生，只有 lastStatus 分得开：
                // 常驻中是个可以自己解开的时序问题，而拓扑/能力不满足不是。
                // 后者不写成「去改 CPU 核数」——多核所需的私有 EPT 请求位在当前
                // 驱动里送不进 PREPARE 的白名单，那条路走不通，不该把人引过去。
                if (result.response.lastStatus == kViewStatusDeviceBusy)
                {
                    reason = ks::i18n::sourceText(
                        QStringLiteral("正在常驻：常驻期间视图表、EPT 叶项与影子页都被锁为不可变，请先停止常驻再安装"));
                }
                else if (result.response.lastStatus == kViewStatusNotSupported)
                {
                    reason = ks::i18n::sourceText(
                        QStringLiteral("拓扑或能力不满足：多处理器上安装视图需要每处理器私有 EPT 层次，而该请求位当前无法通过协议送达驱动；此外处理器必须支持单上下文 INVEPT，使用默认后端时还必须支持 Monitor Trap Flag"));
                }
                else
                {
                    reason = ks::i18n::sourceText(
                        QStringLiteral("视图翻转共享叶项，只能在单处理器且未常驻时安装"));
                }
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

        // toDomainResult：把驱动执行域响应翻译成 UI 可直接展示的结论。
        KvmDomainResult toDomainResult(
            const ksword::ark::HvmDomainResult& result,
            const QString& actionName)
        {
            KvmDomainResult domain;
            domain.domainIndex = result.response.domainIndex;
            domain.domainCount = result.response.domainCount;
            domain.ok = result.io.ok &&
                result.response.status == KSWORD_ARK_HVM_DOMAIN_STATUS_OK;
            if (domain.ok)
            {
                const unsigned long rows =
                    result.response.returnedRows <=
                        KSWORD_ARK_HVM_MAX_DOMAIN_ROWS
                        ? result.response.returnedRows
                        : KSWORD_ARK_HVM_MAX_DOMAIN_ROWS;
                for (unsigned long index = 0; index < rows; ++index)
                {
                    const auto& row = result.response.rows[index];
                    KvmDomainEntry entry;
                    entry.domainIndex = row.domainIndex;
                    entry.active = row.active != 0;
                    entry.privateTableCount = row.privateTableCount;
                    entry.eptPointer = row.eptPointer;
                    domain.domains.append(entry);
                }
                domain.message = ks::i18n::sourceText(
                    QStringLiteral("%1 成功。")).arg(actionName);
                return domain;
            }
            if (!result.io.ok && result.unsupported)
            {
                domain.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：当前驱动不提供该能力。"))
                    .arg(actionName);
                return domain;
            }
            QString reason;
            switch (result.response.status)
            {
            case KSWORD_ARK_HVM_DOMAIN_STATUS_CONFIRMATION_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral("需要显式确认"));
                break;
            case KSWORD_ARK_HVM_DOMAIN_STATUS_NOT_PREPARED:
                reason = ks::i18n::sourceText(QStringLiteral("资源尚未准备"));
                break;
            case KSWORD_ARK_HVM_DOMAIN_STATUS_NOT_FOUND:
                reason = ks::i18n::sourceText(
                    QStringLiteral("没有这个域，或者范围不在恒等映射窗口里"));
                break;
            case KSWORD_ARK_HVM_DOMAIN_STATUS_TABLE_FULL:
                reason = ks::i18n::sourceText(
                    QStringLiteral("域已用尽，或该域分叉的页表已达上限"));
                break;
            case KSWORD_ARK_HVM_DOMAIN_STATUS_EXECUTE_ONLY_UNSUPPORTED:
                reason = ks::i18n::sourceText(
                    QStringLiteral("处理器不支持仅执行的 EPT 叶项，拿不掉读权限"));
                break;
            case KSWORD_ARK_HVM_DOMAIN_STATUS_UNSUPPORTED:
                reason = ks::i18n::sourceText(
                    QStringLiteral("处理器不提供 EPTP 切换，域建了也切不过去"));
                break;
            case KSWORD_ARK_HVM_DOMAIN_STATUS_RESIDENT_ACTIVE:
                reason = ks::i18n::sourceText(
                    QStringLiteral("常驻期间不能改域：可能有 VCPU 正在这些表里执行"));
                break;
            case KSWORD_ARK_HVM_DOMAIN_STATUS_RESOURCE_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("页表分叉失败"));
                break;
            default:
                reason = ks::i18n::sourceText(QStringLiteral("协议状态 %1"))
                    .arg(result.response.status);
                break;
            }
            domain.message = ks::i18n::sourceText(QStringLiteral("%1 失败：%2。"))
                .arg(actionName)
                .arg(reason);
            return domain;
        }

        // denyDomainWithoutWriteAccess：写权限关闭时统一拒绝，不发起 IOCTL。
        KvmDomainResult denyDomainWithoutWriteAccess(const QString& actionName)
        {
            KvmDomainResult domain;
            domain.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：R-1 写权限未开启。"))
                .arg(actionName);
            return domain;
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

    KvmDomainResult listDomains()
    {
        ksword::ark::DriverClient client;
        const auto result = client.controlHvmDomain(
            KSWORD_ARK_HVM_DOMAIN_OP_QUERY,
            0, 0, 0, 0, 0, false);
        return toDomainResult(
            result,
            ks::i18n::sourceText(QStringLiteral("读取 EPT 执行域")));
    }

    KvmDomainResult createDomain()
    {
        const QString actionName =
            ks::i18n::sourceText(QStringLiteral("创建 EPT 执行域"));
        if (!isWriteAccessEnabled())
        {
            return denyDomainWithoutWriteAccess(actionName);
        }
        ksword::ark::DriverClient client;
        const auto result = client.controlHvmDomain(
            KSWORD_ARK_HVM_DOMAIN_OP_CREATE,
            0, 0, 0, 0, 0, true);
        return toDomainResult(result, actionName);
    }

    KvmDomainResult restrictDomain(
        const unsigned long domainIndex,
        const unsigned long long physicalAddress,
        const unsigned long long byteCount,
        const unsigned long deniedAccess)
    {
        const QString actionName =
            ks::i18n::sourceText(QStringLiteral("收紧 EPT 执行域权限"));
        if (!isWriteAccessEnabled())
        {
            return denyDomainWithoutWriteAccess(actionName);
        }
        // 域 0 是默认视图，收紧它等于收紧所有域，驱动会拒绝。这里先挡一次，
        // 免得用户以为自己在改一个副本。
        if (domainIndex == 0)
        {
            KvmDomainResult domain;
            domain.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：0 号是默认视图，收紧它会影响所有域。"))
                .arg(actionName);
            return domain;
        }
        ksword::ark::DriverClient client;
        const auto result = client.controlHvmDomain(
            KSWORD_ARK_HVM_DOMAIN_OP_RESTRICT,
            domainIndex,
            0,
            physicalAddress,
            byteCount,
            deniedAccess,
            true);
        return toDomainResult(result, actionName);
    }

    KvmDomainResult resetDomains()
    {
        const QString actionName =
            ks::i18n::sourceText(QStringLiteral("清空 EPT 执行域"));
        if (!isWriteAccessEnabled())
        {
            return denyDomainWithoutWriteAccess(actionName);
        }
        ksword::ark::DriverClient client;
        const auto result = client.controlHvmDomain(
            KSWORD_ARK_HVM_DOMAIN_OP_RESET,
            0, 0, 0, 0, 0, true);
        return toDomainResult(result, actionName);
    }

    namespace
    {
        // toMsrPolicyResult：把驱动策略响应翻译成 UI 可直接展示的结论。
        KvmMsrPolicyResult toMsrPolicyResult(
            const ksword::ark::HvmMsrPolicyResult& result,
            const QString& actionName)
        {
            KvmMsrPolicyResult policy;
            policy.policyId = result.response.policyId;
            policy.policyCount = result.response.policyCount;
            policy.ok = result.io.ok &&
                result.response.status ==
                    KSWORD_ARK_HVM_MSR_POLICY_STATUS_OK;
            if (policy.ok)
            {
                const unsigned long rows =
                    result.response.returnedRows <=
                        KSWORD_ARK_HVM_MAX_MSR_POLICIES
                        ? result.response.returnedRows
                        : KSWORD_ARK_HVM_MAX_MSR_POLICIES;
                for (unsigned long index = 0; index < rows; ++index)
                {
                    const auto& row = result.response.rows[index];
                    KvmMsrPolicyEntry entry;
                    entry.policyId = row.policyId;
                    entry.msrIndex = row.msrIndex;
                    entry.access = row.access;
                    entry.action = row.action;
                    entry.fakeValue = row.fakeValue;
                    entry.hitCount = row.hitCount;
                    policy.policies.append(entry);
                }
                policy.message = ks::i18n::sourceText(
                    QStringLiteral("%1 成功。")).arg(actionName);
                return policy;
            }
            if (!result.io.ok && result.unsupported)
            {
                policy.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：当前驱动不提供该能力。"))
                    .arg(actionName);
                return policy;
            }
            QString reason;
            switch (result.response.status)
            {
            case KSWORD_ARK_HVM_MSR_POLICY_STATUS_CONFIRMATION_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral("需要显式确认"));
                break;
            case KSWORD_ARK_HVM_MSR_POLICY_STATUS_NOT_PREPARED:
                reason = ks::i18n::sourceText(QStringLiteral("资源尚未准备"));
                break;
            case KSWORD_ARK_HVM_MSR_POLICY_STATUS_NOT_FOUND:
                reason = ks::i18n::sourceText(QStringLiteral("没有这条策略"));
                break;
            case KSWORD_ARK_HVM_MSR_POLICY_STATUS_TABLE_FULL:
                reason = ks::i18n::sourceText(QStringLiteral("策略表已满"));
                break;
            case KSWORD_ARK_HVM_MSR_POLICY_STATUS_INDEX_UNCOVERED:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "该 MSR 索引不在位图覆盖的两段范围内"));
                break;
            case KSWORD_ARK_HVM_MSR_POLICY_STATUS_WRITE_LOG_UNSAFE:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "写方向不支持“记录后放行”：在 VMX root 里重放 WRMSR 没有退路"));
                break;
            case KSWORD_ARK_HVM_MSR_POLICY_STATUS_RESIDENT_BUSY:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "常驻期间不能改动策略，请先停止常驻"));
                break;
            case KSWORD_ARK_HVM_MSR_POLICY_STATUS_DUPLICATE:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "该索引与方向上已有一条策略"));
                break;
            default:
                reason = ks::i18n::sourceText(QStringLiteral("协议状态 %1"))
                    .arg(result.response.status);
                break;
            }
            policy.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：%2。"))
                .arg(actionName)
                .arg(reason);
            return policy;
        }

        // denyMsrPolicyWithoutWriteAccess：写权限关闭时统一拒绝，不发 IOCTL。
        KvmMsrPolicyResult denyMsrPolicyWithoutWriteAccess(
            const QString& actionName)
        {
            KvmMsrPolicyResult policy;
            policy.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：R-1 写权限未开启。"))
                .arg(actionName);
            return policy;
        }
    }

    KvmMsrPolicyResult listMsrPolicies()
    {
        ksword::ark::DriverClient client;
        const auto result = client.controlHvmMsrPolicy(
            KSWORD_ARK_HVM_MSR_POLICY_OP_QUERY,
            0, 0, 0, 0, 0, false);
        return toMsrPolicyResult(
            result,
            ks::i18n::sourceText(QStringLiteral("读取 MSR 策略")));
    }

    KvmMsrPolicyResult addMsrPolicy(
        const unsigned long msrIndex,
        const unsigned long access,
        const unsigned long action,
        const unsigned long long fakeValue)
    {
        const QString actionName =
            ks::i18n::sourceText(QStringLiteral("安装 MSR 策略"));
        if (!isWriteAccessEnabled())
        {
            return denyMsrPolicyWithoutWriteAccess(actionName);
        }
        ksword::ark::DriverClient client;
        const auto result = client.controlHvmMsrPolicy(
            KSWORD_ARK_HVM_MSR_POLICY_OP_ADD,
            0,
            msrIndex,
            access,
            action,
            fakeValue,
            true);
        return toMsrPolicyResult(result, actionName);
    }

    KvmMsrPolicyResult removeMsrPolicy(const unsigned long policyId)
    {
        const QString actionName =
            ks::i18n::sourceText(QStringLiteral("移除 MSR 策略"));
        if (!isWriteAccessEnabled())
        {
            return denyMsrPolicyWithoutWriteAccess(actionName);
        }
        ksword::ark::DriverClient client;
        const auto result = client.controlHvmMsrPolicy(
            KSWORD_ARK_HVM_MSR_POLICY_OP_REMOVE,
            policyId, 0, 0, 0, 0, true);
        return toMsrPolicyResult(result, actionName);
    }

    KvmMsrPolicyResult clearMsrPolicies()
    {
        const QString actionName =
            ks::i18n::sourceText(QStringLiteral("清空 MSR 策略"));
        if (!isWriteAccessEnabled())
        {
            return denyMsrPolicyWithoutWriteAccess(actionName);
        }
        ksword::ark::DriverClient client;
        const auto result = client.controlHvmMsrPolicy(
            KSWORD_ARK_HVM_MSR_POLICY_OP_CLEAR,
            0, 0, 0, 0, 0, true);
        return toMsrPolicyResult(result, actionName);
    }

    KvmEventResult readEvents(
        const unsigned long long afterSequence,
        const bool clear)
    {
        KvmEventResult events;
        ksword::ark::DriverClient client;
        const auto result = client.queryHvmEvents(
            afterSequence,
            KSWORD_ARK_HVM_MAX_EVENT_ROWS,
            clear);
        events.ok = result.io.ok;
        if (!events.ok)
        {
            events.message = result.unsupported
                ? ks::i18n::sourceText(
                    QStringLiteral("读取 HVM 事件失败：当前驱动不提供该能力。"))
                : ks::i18n::sourceText(
                    QStringLiteral("读取 HVM 事件失败。"));
            return events;
        }
        events.droppedRows = result.response.droppedRows;
        events.availableRows = result.response.availableRows;
        events.newestSequence = result.response.newestSequence;
        const unsigned long rows =
            result.response.returnedRows <= KSWORD_ARK_HVM_MAX_EVENT_ROWS
                ? result.response.returnedRows
                : KSWORD_ARK_HVM_MAX_EVENT_ROWS;
        for (unsigned long index = 0; index < rows; ++index)
        {
            const auto& row = result.response.rows[index];
            KvmEventEntry entry;
            entry.sequence = row.sequence;
            entry.timestamp = row.timestamp;
            entry.guestPhysicalAddress = row.guestPhysicalAddress;
            entry.guestLinearAddress = row.guestLinearAddress;
            entry.guestRip = row.guestRip;
            entry.qualification = row.qualification;
            entry.processorGroup = row.processorGroup;
            entry.processorNumber = row.processorNumber;
            entry.type = row.type;
            entry.exitReason = row.exitReason;
            entry.access = row.access;
            entry.ruleId = row.ruleId;
            entry.status = row.status;
            events.events.append(entry);
        }
        return events;
    }

    namespace
    {
        // toCrPolicyResult：把驱动响应翻译成 UI 可直接展示的结论。
        KvmCrPolicyResult toCrPolicyResult(
            const ksword::ark::HvmCrPolicyResult& result,
            const QString& actionName)
        {
            KvmCrPolicyResult policy;
            policy.cr0PinnedMask = result.response.cr0PinnedMask;
            policy.cr4PinnedMask = result.response.cr4PinnedMask;
            policy.cr0PinnedValue = result.response.cr0PinnedValue;
            policy.cr4PinnedValue = result.response.cr4PinnedValue;
            policy.refusedWriteCount = result.response.refusedWriteCount;
            policy.cr3SwitchCount = result.response.cr3SwitchCount;
            policy.debugAccessCount = result.response.debugAccessCount;
            policy.trackCr3 = (result.response.flags &
                KSWORD_ARK_HVM_CR_POLICY_FLAG_TRACK_CR3) != 0;
            policy.interceptDr = (result.response.flags &
                KSWORD_ARK_HVM_CR_POLICY_FLAG_INTERCEPT_DR) != 0;
            policy.log = (result.response.flags &
                KSWORD_ARK_HVM_CR_POLICY_FLAG_LOG) != 0;
            policy.ok = result.io.ok &&
                result.response.status ==
                    KSWORD_ARK_HVM_CR_POLICY_STATUS_OK;
            if (policy.ok)
            {
                policy.message = ks::i18n::sourceText(
                    QStringLiteral("%1 成功。")).arg(actionName);
                return policy;
            }
            if (!result.io.ok && result.unsupported)
            {
                policy.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：当前驱动不提供该能力。"))
                    .arg(actionName);
                return policy;
            }
            QString reason;
            switch (result.response.status)
            {
            case KSWORD_ARK_HVM_CR_POLICY_STATUS_CONFIRMATION_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral("需要显式确认"));
                break;
            case KSWORD_ARK_HVM_CR_POLICY_STATUS_NOT_PREPARED:
                reason = ks::i18n::sourceText(QStringLiteral("资源尚未准备"));
                break;
            case KSWORD_ARK_HVM_CR_POLICY_STATUS_RESIDENT_BUSY:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "掩码在建 VMCS 时消费，常驻期间改动不会生效，已拒绝"));
                break;
            case KSWORD_ARK_HVM_CR_POLICY_STATUS_BIT_NOT_PINNABLE:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "该位被固定位 MSR 强制，钉住它会让每次 VM entry 失败"));
                break;
            default:
                reason = ks::i18n::sourceText(QStringLiteral("协议状态 %1"))
                    .arg(result.response.status);
                break;
            }
            policy.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：%2。"))
                .arg(actionName)
                .arg(reason);
            return policy;
        }
    }

    KvmCrPolicyResult readCrPolicy()
    {
        ksword::ark::DriverClient client;
        const auto result = client.controlHvmCrPolicy(
            KSWORD_ARK_HVM_CR_POLICY_OP_QUERY,
            0, 0, false, false, false, false);
        return toCrPolicyResult(
            result,
            ks::i18n::sourceText(QStringLiteral("读取控制寄存器策略")));
    }

    KvmCrPolicyResult applyCrPolicy(
        const unsigned long long cr0PinnedMask,
        const unsigned long long cr4PinnedMask,
        const bool trackCr3,
        const bool interceptDr,
        const bool log)
    {
        const QString actionName =
            ks::i18n::sourceText(QStringLiteral("配置控制寄存器策略"));
        if (!isWriteAccessEnabled())
        {
            KvmCrPolicyResult policy;
            policy.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：R-1 写权限未开启。"))
                .arg(actionName);
            return policy;
        }
        ksword::ark::DriverClient client;
        const auto result = client.controlHvmCrPolicy(
            KSWORD_ARK_HVM_CR_POLICY_OP_SET,
            cr0PinnedMask,
            cr4PinnedMask,
            trackCr3,
            interceptDr,
            log,
            true);
        return toCrPolicyResult(result, actionName);
    }

    KvmCrPolicyResult clearCrPolicy()
    {
        const QString actionName =
            ks::i18n::sourceText(QStringLiteral("清除控制寄存器策略"));
        if (!isWriteAccessEnabled())
        {
            KvmCrPolicyResult policy;
            policy.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：R-1 写权限未开启。"))
                .arg(actionName);
            return policy;
        }
        ksword::ark::DriverClient client;
        const auto result = client.controlHvmCrPolicy(
            KSWORD_ARK_HVM_CR_POLICY_OP_CLEAR,
            0, 0, false, false, false, true);
        return toCrPolicyResult(result, actionName);
    }
}
