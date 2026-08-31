#include "KernelKnowledgeCatalog.h"

#include "../Internationalization/LanguageManager.h"

#include <algorithm>

namespace ks::kernel_knowledge
{
    const std::vector<CategoryDefinition>& categories()
    {
        // 分类引用只指向微软公开文档；私有结构结论仍由每篇文章明确标成 PDB/DynData 证据。
        static const std::vector<CategoryDefinition> catalog{
            { "execution_basics", "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-hardware-priorities" },
            { "driver_model", "https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/" },
            { "object_manager", "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-kernel-objects" },
            { "cid_handles", "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles" },
            { "process_thread", "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-process-and-thread-manager" },
            { "memory", "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-memory-for-drivers" },
            { "io_storage", "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-i-o-manager" },
            { "registry", "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/filtering-registry-calls" },
            { "security", "https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/driver-security-checklist" },
            { "network_ipc_gui", "https://learn.microsoft.com/en-us/windows-hardware/drivers/network/" },
            { "hardware_power", "https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-plug-and-play" },
            { "observability", "https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/wpp-software-tracing" }
        };
        return catalog;
    }

    const std::vector<TopicDefinition>& topics()
    {
        // 71 项与共享 Research topic ID 和《第二规划》逐条同序。
        // 每一项都可采集版本化 R0 现场证据，routeId 再定位到对应的业务采集页。
        static const std::vector<TopicDefinition> catalog{
            { "execution_chain", "execution_basics", Coverage::Available, "io_management" },
            { "address_spaces", "execution_basics", Coverage::Available, "slat_iommu" },
            { "handles_references", "execution_basics", Coverage::Available, "object_namespace" },
            { "status_codes", "execution_basics", Coverage::Available, "io_management" },
            { "irql_context", "execution_basics", Coverage::Available, "timer_dpc" },
            { "synchronization", "execution_basics", Coverage::Available, "timer_dpc" },
            { "driver_lifecycle", "driver_model", Coverage::Available, "object_namespace" },
            { "wdm_kmdf", "driver_model", Coverage::Available, "io_management" },
            { "ioctl_chain", "driver_model", Coverage::Available, "io_management" },
            { "debugging_dumps", "driver_model", Coverage::Available, "kernel_audit" },
            { "object_manager", "object_manager", Coverage::Available, "object_namespace" },
            { "object_directories", "object_manager", Coverage::Available, "object_namespace" },
            { "symbolic_links", "object_manager", Coverage::Available, "object_namespace" },
            { "object_header", "object_manager", Coverage::Available, "object_namespace" },
            { "object_security", "object_manager", Coverage::Available, "object_namespace" },
            { "psp_cid_table", "cid_handles", Coverage::Available, "cid" },
            { "cid_object_relations", "cid_handles", Coverage::Available, "cid" },
            { "handle_table_tablecode", "cid_handles", Coverage::Available, "cid" },
            { "process_cross_view", "cid_handles", Coverage::Available, "cid" },
            { "process_vs_cid_handles", "cid_handles", Coverage::Available, "cid" },
            { "cross_view_visualization", "cid_handles", Coverage::Available, "cid" },
            { "executive_thread_objects", "process_thread", Coverage::Available, "cid" },
            { "process_lifecycle", "process_thread", Coverage::Available, "cid" },
            { "scheduler", "process_thread", Coverage::Available, "work_queue_threads" },
            { "dispatcher_objects", "process_thread", Coverage::Available, "timer_dpc" },
            { "apc_dpc_work_items", "process_thread", Coverage::Available, "timer_dpc" },
            { "process_attach", "process_thread", Coverage::Available, "cid" },
            { "session_silo_pico", "process_thread", Coverage::Available, "cid" },
            { "page_tables", "memory", Coverage::Available, "slat_iommu" },
            { "page_fault_working_set", "memory", Coverage::Available, "slat_iommu" },
            { "vad", "memory", Coverage::Available, "object_namespace" },
            { "pfn_database", "memory", Coverage::Available, "slat_iommu" },
            { "section_control_area", "memory", Coverage::Available, "object_namespace" },
            { "mdl_dma", "memory", Coverage::Available, "slat_iommu" },
            { "pool", "memory", Coverage::Available, "text_integrity" },
            { "executable_memory_evidence", "memory", Coverage::Available, "text_integrity" },
            { "irp_lifecycle", "io_storage", Coverage::Available, "io_management" },
            { "driver_device_file_objects", "io_storage", Coverage::Available, "object_namespace" },
            { "minifilter", "io_storage", Coverage::Available, "kernel_audit" },
            { "cache_memory_manager", "io_storage", Coverage::Available, "object_namespace" },
            { "filesystems", "io_storage", Coverage::Available, "object_namespace" },
            { "storage_stack", "io_storage", Coverage::Available, "object_namespace" },
            { "network_redirector", "io_storage", Coverage::Available, "ipc" },
            { "registry_views", "registry", Coverage::Available, "object_namespace" },
            { "configuration_manager", "registry", Coverage::Available, "object_namespace" },
            { "registry_callbacks", "registry", Coverage::Available, "kernel_audit" },
            { "registry_transactions", "registry", Coverage::Available, "kernel_audit" },
            { "token", "security", Coverage::Available, "cid" },
            { "authentication_stack", "security", Coverage::Available, "vbs" },
            { "protected_process", "security", Coverage::Available, "cid" },
            { "code_integrity", "security", Coverage::Available, "text_integrity" },
            { "vbs_hvci", "security", Coverage::Available, "vbs" },
            { "patchguard", "security", Coverage::Available, "text_integrity" },
            { "network_stack", "network_ipc_gui", Coverage::Available, "ipc" },
            { "wfp_ndis", "network_ipc_gui", Coverage::Available, "kernel_audit" },
            { "afd_nsi", "network_ipc_gui", Coverage::Available, "ipc" },
            { "alpc", "network_ipc_gui", Coverage::Available, "ipc" },
            { "ipc", "network_ipc_gui", Coverage::Available, "ipc" },
            { "win32k_gui", "network_ipc_gui", Coverage::Available, "kernel_audit" },
            { "pnp", "hardware_power", Coverage::Available, "object_namespace" },
            { "device_stack", "hardware_power", Coverage::Available, "object_namespace" },
            { "acpi_pci", "hardware_power", Coverage::Available, "slat_iommu" },
            { "usb_hid", "hardware_power", Coverage::Available, "object_namespace" },
            { "gpu_tdr", "hardware_power", Coverage::Available, "object_namespace" },
            { "power_management", "hardware_power", Coverage::Available, "slat_iommu" },
            { "callbacks", "observability", Coverage::Available, "kernel_audit" },
            { "external_callbacks", "observability", Coverage::Available, "kernel_audit" },
            { "hook_evidence", "observability", Coverage::Available, "kernel_audit" },
            { "cpu_control_state", "observability", Coverage::Available, "io_management" },
            { "tracing", "observability", Coverage::Available, "kernel_audit" },
            { "evidence_timeline", "observability", Coverage::Available, "cid" }
        };
        return catalog;
    }

    const CategoryDefinition* categoryForTopic(const TopicDefinition& topic)
    {
        const auto& catalog = categories();
        const auto match = std::find_if(
            catalog.cbegin(),
            catalog.cend(),
            [&topic](const CategoryDefinition& category)
            {
                return QString::fromLatin1(category.id) == QString::fromLatin1(topic.categoryId);
            });
        return match != catalog.cend() ? &(*match) : nullptr;
    }

    QString categoryText(const CategoryDefinition& category, const char* field)
    {
        const QString key = QStringLiteral("kernel.knowledge.category.%1.%2")
            .arg(QString::fromLatin1(category.id), QString::fromLatin1(field));
        return ks::i18n::text(key);
    }

    QString topicText(const TopicDefinition& topic, const char* field)
    {
        const QString key = QStringLiteral("kernel.knowledge.topic.%1.%2")
            .arg(QString::fromLatin1(topic.id), QString::fromLatin1(field));
        return ks::i18n::text(key);
    }

    QString coverageText(const Coverage coverage)
    {
        const char* keySuffix = "planned";
        switch (coverage)
        {
        case Coverage::Available:
            keySuffix = "available";
            break;
        case Coverage::AvailableNeedsExplanation:
            keySuffix = "needs_explanation";
            break;
        case Coverage::Partial:
            keySuffix = "partial";
            break;
        case Coverage::Planned:
            keySuffix = "planned";
            break;
        }

        const QString key = QStringLiteral("kernel.knowledge.coverage.%1")
            .arg(QString::fromLatin1(keySuffix));
        return ks::i18n::text(key);
    }
}
