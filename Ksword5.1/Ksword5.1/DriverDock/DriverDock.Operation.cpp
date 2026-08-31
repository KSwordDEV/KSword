#include "DriverDock.Internal.h"
#include "DriverDock.ModuleDumpFile.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../OnlineScan/SandboxUploadActions.h"
#include "../UI/TableInteractionSupport.h"

#include <QDesktopServices>
#include <QUrl>
#include <QUrlQuery>
#include <QVariant>

// 说明：由原聚合式实现迁移为独立 .cpp，成员函数实现保持原样。
using namespace ksword::driver_dock_internal;

namespace
{
    bool openDriverBingSearch(
        const QString& driverName,
        const QString& driverImagePath)
    {
        // openDriverBingSearch：
        // - 输入：右键菜单打开前快照的驱动名与镜像路径；
        // - 处理：只构造 Bing 查询 URL 并交给系统默认浏览器，不读取任何搜索结果；
        // - 返回：系统是否接受了 URL 打开请求。
        QStringList queryTerms;
        const QString normalizedName = driverName.trimmed();
        if (!normalizedName.isEmpty())
        {
            queryTerms.push_back(normalizedName);
        }

        // 路径只取文件名，避免把用户机器目录或设备路径发送给搜索引擎。
        const QString imageFileName = QFileInfo(driverImagePath.trimmed()).fileName();
        if (!imageFileName.isEmpty() &&
            imageFileName.compare(normalizedName, Qt::CaseInsensitive) != 0)
        {
            queryTerms.push_back(imageFileName);
        }
        queryTerms.push_back(QStringLiteral("Windows driver"));

        QUrl searchUrl(QStringLiteral("https://www.bing.com/search"));
        QUrlQuery searchQuery;
        searchQuery.addQueryItem(QStringLiteral("q"), queryTerms.join(QLatin1Char(' ')));
        searchUrl.setQuery(searchQuery);
        return QDesktopServices::openUrl(searchUrl);
    }

    QString driverOperationTableCellText(QTableWidget* table, const int rowIndex, const int columnIndex)
    {
        // driverOperationTableCellText：
        // - 输入：表格、行号、列号；
        // - 处理：安全读取单元格文本；
        // - 返回：单元格不存在时返回空字符串。
        if (table == nullptr)
        {
            return QString();
        }
        const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
        return item != nullptr ? item->text() : QString();
    }

    void copyDriverOperationCurrentRow(QTableWidget* table)
    {
        // copyDriverOperationCurrentRow：
        // - 输入：服务表或模块表；
        // - 处理：复制当前行 TSV；
        // - 返回：无，不触发任何驱动操作。
        if (table == nullptr || QGuiApplication::clipboard() == nullptr)
        {
            return;
        }

        const int rowIndex = table->currentRow();
        if (rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return;
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            fields.push_back(driverOperationTableCellText(table, rowIndex, columnIndex));
        }
        QGuiApplication::clipboard()->setText(fields.join(QLatin1Char('\t')));
    }

    QString buildKernelSignatureNtPath(const QString& rawPathText)
    {
        QString pathText = ks::online_scan::normalizeKernelImagePathForUpload(rawPathText).trimmed();
        pathText.replace(QLatin1Char('/'), QLatin1Char('\\'));
        if (pathText.isEmpty())
        {
            return QString();
        }
        if (pathText.startsWith(QStringLiteral("\\??\\")) ||
            pathText.startsWith(QStringLiteral("\\Device\\"), Qt::CaseInsensitive) ||
            pathText.startsWith(QStringLiteral("\\SystemRoot\\"), Qt::CaseInsensitive))
        {
            return pathText;
        }
        if (pathText.startsWith(QStringLiteral("\\\\?\\")))
        {
            return QStringLiteral("\\??\\") + pathText.mid(4);
        }
        if (pathText.startsWith(QStringLiteral("\\\\")))
        {
            return QStringLiteral("\\??\\UNC\\") + pathText.mid(2);
        }
        return QStringLiteral("\\??\\") + pathText;
    }

    // integrityClassText：
    // - 输入：Driver Integrity 证据类别常量；
    // - 处理：把类别映射为 DriverDock 侧可读文本；
    // - 返回：类别名称，未知值保留数值信息。
    QString integrityClassText(const std::uint32_t evidenceClass)
    {
        switch (evidenceClass)
        {
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW: return QStringLiteral("ModuleView");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_PS_LOADED_MODULES: return QStringLiteral("PsLoadedModules");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT: return QStringLiteral("DriverObject");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION: return QStringLiteral("DriverSection");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MAJOR_FUNCTION: return QStringLiteral("MajorFunction");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_FAST_IO: return QStringLiteral("FastIo");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN: return QStringLiteral("DeviceChain");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_SERVICE: return QStringLiteral("Service");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_CPU_CONTROL: return QStringLiteral("CPU");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DESCRIPTOR_TABLE: return QStringLiteral("Descriptor");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MSR_ENTRY: return QStringLiteral("MSR");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER: return QStringLiteral("IDT");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL: return QStringLiteral("OptionalGlobal");
        default: return QStringLiteral("Class(%1)").arg(evidenceClass);
        }
    }

    // integrityRiskText：
    // - 输入：Driver Integrity 风险位；
    // - 处理：转换为短文本，便于在证据页直接浏览；
    // - 返回：空风险显示“正常”。
    QString integrityRiskText(const std::uint32_t flags)
    {
        if (flags == 0U)
        {
            return driverText("driver.integrity.risk.normal", QStringLiteral("正常"));
        }
        QStringList parts;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE)
            parts << driverText("driver.integrity.risk.unavailable", QStringLiteral("不可用"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED)
            parts << driverText("driver.integrity.risk.query_failed", QStringLiteral("查询失败"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED)
            parts << driverText("driver.integrity.risk.module_unresolved", QStringLiteral("模块未解析"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH)
            parts << driverText("driver.integrity.risk.owner_mismatch", QStringLiteral("Owner不匹配"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE)
            parts << driverText("driver.integrity.risk.outside_image", QStringLiteral("外跳"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH)
            parts << driverText("driver.integrity.risk.section_mismatch", QStringLiteral("Section不匹配"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_SERVICE_MISSING)
            parts << driverText("driver.integrity.risk.service_missing", QStringLiteral("服务缺失"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_EMPTY_UNLOAD)
            parts << driverText("driver.integrity.risk.empty_unload", QStringLiteral("Unload为空"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DEVICE_LOOP)
            parts << driverText("driver.integrity.risk.device_loop", QStringLiteral("Device环"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_ATTACHED_LOOP)
            parts << driverText("driver.integrity.risk.attached_loop", QStringLiteral("Attached环"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH)
            parts << driverText("driver.integrity.risk.cross_driver_attach", QStringLiteral("跨驱动挂接"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_NULL_POINTER)
            parts << driverText("driver.integrity.risk.null_pointer", QStringLiteral("空指针"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER)
            parts << driverText("driver.integrity.risk.idt_external_owner", QStringLiteral("IDT外部Owner"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED)
            parts << driverText("driver.integrity.risk.wp_disabled", QStringLiteral("WP关闭"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED)
            parts << driverText("driver.integrity.risk.nxe_disabled", QStringLiteral("NXE关闭"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED)
            parts << driverText("driver.integrity.risk.smep_disabled", QStringLiteral("SMEP关闭"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED)
            parts << driverText("driver.integrity.risk.smap_disabled", QStringLiteral("SMAP关闭"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID)
            parts << driverText("driver.integrity.risk.descriptor_invalid", QStringLiteral("描述符异常"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE)
            parts << driverText("driver.integrity.risk.dyndata_unavailable", QStringLiteral("DynData缺失"));
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED)
            parts << driverText("driver.integrity.risk.truncated", QStringLiteral("截断"));
        return parts.join(QStringLiteral(" | "));
    }

    // appendEvidenceRow：
    // - 输入：通用证据表、行号和字段内容；
    // - 处理：在 6 列证据表中写入一条只读行；
    // - 返回：无。
    void appendEvidenceRow(
        QTableWidget* table,
        const int rowIndex,
        const QString& evidenceText,
        const QString& objectText,
        const QString& targetText,
        const QString& riskText,
        const QString& confidenceText,
        const QString& detailText)
    {
        if (table == nullptr)
        {
            return;
        }
        table->setItem(rowIndex, 0, createReadOnlyItem(evidenceText));
        table->setItem(rowIndex, 1, createReadOnlyItem(objectText));
        table->setItem(rowIndex, 2, createReadOnlyItem(targetText));
        table->setItem(rowIndex, 3, createReadOnlyItem(riskText));
        table->setItem(rowIndex, 4, createReadOnlyItem(confidenceText));
        table->setItem(rowIndex, 5, createReadOnlyItem(detailText));
    }

    constexpr std::uint32_t kDriverModuleDumpHeaderProbeBytes = 64U * 1024U;
    constexpr std::uint32_t kDriverModuleDumpHardMaxBytes = 512U * 1024U * 1024U;

    enum class DriverModuleDumpError : std::uint32_t
    {
        None = 0U,
        InvalidTarget,
        TargetExists,
        IdentityCheck,
        DeviceOpen,
        MemoryRead,
        PeValidation,
        DestinationDirectory,
        TemporaryFileCreate,
        TemporaryFileWrite,
        TemporaryFileFlush,
        AtomicCommit
    };

    struct DriverModuleDumpResult
    {
        bool ok = false;
        DriverModuleDumpError error = DriverModuleDumpError::None;
        QString technicalDetail;
        QString targetPath;
        std::uint64_t moduleBase = 0U;
        std::uint32_t moduleSize = 0U;
        // zeroFilledChunkCount：记录 R0 因不可读或已释放页面而补零的读取分块数。
        std::uint32_t zeroFilledChunkCount = 0U;
        unsigned long win32Error = ERROR_SUCCESS;
    };

    QString driverModuleDumpErrorText(const DriverModuleDumpError error)
    {
        switch (error)
        {
        case DriverModuleDumpError::InvalidTarget:
            return driverText(
                "driver.dump_module.error.invalid_target",
                QStringLiteral("模块身份参数或保存路径不安全，操作已拒绝。"));
        case DriverModuleDumpError::TargetExists:
            return driverText(
                "driver.dump_module.error.target_exists",
                QStringLiteral("目标文件已存在或在提交前被创建；为避免覆盖，操作已取消。"));
        case DriverModuleDumpError::IdentityCheck:
            return driverText(
                "driver.dump_module.error.identity_check",
                QStringLiteral("R0 无法确认读取前后的模块基址、名称和大小完全一致。"));
        case DriverModuleDumpError::DeviceOpen:
            return driverText(
                "driver.dump_module.error.device_open",
                QStringLiteral("无法打开 KswordARK R0 控制设备。"));
        case DriverModuleDumpError::MemoryRead:
            return driverText(
                "driver.dump_module.error.memory_read",
                QStringLiteral("R0 内存读取响应的协议字段或数据长度未通过完整性校验，未保留无效数据。"));
        case DriverModuleDumpError::PeValidation:
            return driverText(
                "driver.dump_module.error.pe_validation",
                QStringLiteral("内存中的 PE 头或 SizeOfImage 与 R0 模块边界不一致。"));
        case DriverModuleDumpError::DestinationDirectory:
            return driverText(
                "driver.dump_module.error.destination_directory",
                QStringLiteral("目标目录不存在或不可安全使用。"));
        case DriverModuleDumpError::TemporaryFileCreate:
            return driverText(
                "driver.dump_module.error.temp_create",
                QStringLiteral("无法在目标目录创建原子临时文件。"));
        case DriverModuleDumpError::TemporaryFileWrite:
            return driverText(
                "driver.dump_module.error.temp_write",
                QStringLiteral("写入原子临时文件失败，临时文件已取消。"));
        case DriverModuleDumpError::TemporaryFileFlush:
            return driverText(
                "driver.dump_module.error.temp_flush",
                QStringLiteral("原子临时文件无法完整刷新到磁盘，提交已取消。"));
        case DriverModuleDumpError::AtomicCommit:
            return driverText(
                "driver.dump_module.error.atomic_commit",
                QStringLiteral("最终无覆盖原子提交失败，目标文件未创建。"));
        case DriverModuleDumpError::None:
        default:
            return driverText(
                "driver.dump_module.error.unknown",
                QStringLiteral("模块内存 Dump 在安全校验中失败。"));
        }
    }

    template <typename ValueType>
    bool driverModuleDumpReadValue(
        const std::vector<std::uint8_t>& bytes,
        const std::size_t offset,
        ValueType& valueOut)
    {
        if (offset > bytes.size() || sizeof(ValueType) > bytes.size() - offset)
        {
            return false;
        }
        std::memcpy(&valueOut, bytes.data() + offset, sizeof(ValueType));
        return true;
    }

    // driverModuleDumpValidateRead：
    // - 输入：一次 R0 内核读取响应及期望的地址、长度；
    // - 处理：严格校验协议 framing，并只接受完整读取或由 R0 明确标记的补零读取；
    // - 输出：zeroFilledOut 表示该分块包含不可读/已释放页面的 00 占位数据。
    bool driverModuleDumpValidateRead(
        const ksword::ark::VirtualMemoryReadResult& readResult,
        const std::uint64_t expectedAddress,
        const std::uint32_t expectedBytes,
        QString& technicalDetailOut,
        bool& zeroFilledOut)
    {
        zeroFilledOut = false;
        const std::uint32_t requiredFields =
            KSWORD_ARK_MEMORY_FIELD_READ_DATA_PRESENT |
            KSWORD_ARK_MEMORY_FIELD_ADDRESS_KERNEL_RANGE;
        const std::uint32_t zeroFillFields =
            KSWORD_ARK_MEMORY_FIELD_PARTIAL_COPY |
            KSWORD_ARK_MEMORY_FIELD_ZERO_FILLED_UNREADABLE;
        const bool completeRead =
            readResult.readStatus == KSWORD_ARK_MEMORY_READ_STATUS_OK &&
            readResult.copyStatus == 0 &&
            (readResult.fieldFlags & zeroFillFields) == 0U;
        const bool zeroFilledRead =
            (readResult.readStatus == KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY ||
             readResult.readStatus == KSWORD_ARK_MEMORY_READ_STATUS_ZERO_FILLED) &&
            readResult.copyStatus != 0 &&
            (readResult.fieldFlags & zeroFillFields) == zeroFillFields;
        if (!readResult.io.ok ||
            readResult.version != KSWORD_ARK_MEMORY_PROTOCOL_VERSION ||
            readResult.headerSize !=
                offsetof(KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE, data) ||
            readResult.processId != 0U ||
            readResult.source != KSWORD_ARK_MEMORY_SOURCE_R0_MM_COPY_KERNEL_VIRTUAL ||
            readResult.requestedBaseAddress != expectedAddress ||
            readResult.requestedBytes != expectedBytes ||
            readResult.maxBytesPerRequest != KSWORD_ARK_MEMORY_READ_MAX_BYTES ||
            readResult.lookupStatus != 0 ||
            (readResult.fieldFlags & requiredFields) != requiredFields ||
            (readResult.fieldFlags & KSWORD_ARK_MEMORY_FIELD_ADDRESS_USER_RANGE) != 0U ||
            (!completeRead && !zeroFilledRead) ||
            readResult.bytesRead != expectedBytes ||
            readResult.data.size() != static_cast<std::size_t>(expectedBytes) ||
            readResult.io.bytesReturned !=
                offsetof(KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE, data) + expectedBytes)
        {
            technicalDetailOut = QString::fromLatin1(
                "R0 read response rejected: io=%1, win32=%2, version=%3, "
                "pid=%4, source=%5, address=0x%6/0x%7, requested=%8/%9, "
                "returned=%10, bytesRead=%11, data=%12, status=%13, "
                "copyStatus=0x%14, fields=0x%15, max=%16.")
                .arg(readResult.io.ok ? 1 : 0)
                .arg(readResult.io.win32Error)
                .arg(readResult.version)
                .arg(readResult.processId)
                .arg(readResult.source)
                .arg(readResult.requestedBaseAddress, 0, 16)
                .arg(expectedAddress, 0, 16)
                .arg(readResult.requestedBytes)
                .arg(expectedBytes)
                .arg(readResult.io.bytesReturned)
                .arg(readResult.bytesRead)
                .arg(readResult.data.size())
                .arg(readResult.readStatus)
                .arg(static_cast<unsigned long>(readResult.copyStatus), 0, 16)
                .arg(readResult.fieldFlags, 0, 16)
                .arg(readResult.maxBytesPerRequest);
            return false;
        }
        zeroFilledOut = zeroFilledRead;
        return true;
    }

    bool driverModuleDumpQueryIdentity(
        const ksword::ark::DriverClient& driverClient,
        const QString& ntPath,
        const std::uint64_t moduleBase,
        const std::uint32_t expectedSize,
        std::uint32_t& moduleSizeOut,
        QString& technicalDetailOut)
    {
        const ksword::ark::ImageSignatureQueryResult identityResult =
            driverClient.queryImageSignature(
                ntPath.toStdWString(),
                moduleBase,
                KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_MATCH_LOADED_MODULE);
        const KSWORD_ARK_QUERY_IMAGE_SIGNATURE_RESPONSE& response =
            identityResult.response;
        const unsigned long requiredFields =
            KSWORD_ARK_IMAGE_SIGNATURE_FIELD_REQUEST_PATH |
            KSWORD_ARK_IMAGE_SIGNATURE_FIELD_LOADED_MODULE |
            KSWORD_ARK_IMAGE_SIGNATURE_FIELD_LOADED_MODULE_NAME_MATCH;
        std::size_t responsePathLength = 0U;
        while (responsePathLength < KSWORD_ARK_TRUST_PATH_MAX_CHARS &&
               response.ntPath[responsePathLength] != L'\0')
        {
            ++responsePathLength;
        }
        const QString responseNtPath =
            responsePathLength < KSWORD_ARK_TRUST_PATH_MAX_CHARS
            ? QString::fromWCharArray(
                response.ntPath,
                static_cast<int>(responsePathLength))
            : QString();
        if (!identityResult.io.ok ||
            response.requestFlags !=
                KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_MATCH_LOADED_MODULE ||
            response.expectedModuleBase != moduleBase ||
            response.matchedModuleBase != moduleBase ||
            response.loadedModuleStatus != 0 ||
            responseNtPath.compare(ntPath, Qt::CaseSensitive) != 0 ||
            (response.structuralFlags &
                KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_LOADED_NAME_MISMATCH) != 0U ||
            (response.fieldFlags & requiredFields) != requiredFields ||
            response.matchedModuleSize == 0U ||
            response.matchedModuleSize > kDriverModuleDumpHardMaxBytes ||
            (expectedSize != 0U && response.matchedModuleSize != expectedSize) ||
            moduleBase > (std::numeric_limits<std::uint64_t>::max)() -
                static_cast<std::uint64_t>(response.matchedModuleSize))
        {
            technicalDetailOut = QString::fromLatin1(
                "R0 loaded-module identity rejected: io=%1, win32=%2, "
                "expectedBase=0x%3, responseExpected=0x%4, matchedBase=0x%5, "
                "matchedSize=%6, expectedSize=%7, loadedStatus=0x%8, fields=0x%9.")
                .arg(identityResult.io.ok ? 1 : 0)
                .arg(identityResult.io.win32Error)
                .arg(moduleBase, 0, 16)
                .arg(response.expectedModuleBase, 0, 16)
                .arg(response.matchedModuleBase, 0, 16)
                .arg(response.matchedModuleSize)
                .arg(expectedSize)
                .arg(static_cast<unsigned long>(response.loadedModuleStatus), 0, 16)
                .arg(response.fieldFlags, 0, 16);
            return false;
        }
        moduleSizeOut = response.matchedModuleSize;
        return true;
    }

    bool driverModuleDumpValidatePeImage(
        const std::vector<std::uint8_t>& headerBytes,
        const std::uint32_t authoritativeSize,
        QString& technicalDetailOut)
    {
        std::uint16_t dosMagic = 0U;
        std::uint32_t peOffset = 0U;
        if (!driverModuleDumpReadValue(headerBytes, 0U, dosMagic) ||
            !driverModuleDumpReadValue(headerBytes, 0x3CU, peOffset) ||
            dosMagic != 0x5A4DU ||
            peOffset < 0x40U)
        {
            technicalDetailOut = QString::fromLatin1(
                "Loaded image DOS header is invalid (magic=0x%1, e_lfanew=0x%2).")
                .arg(dosMagic, 0, 16)
                .arg(peOffset, 0, 16);
            return false;
        }

        std::uint32_t peSignature = 0U;
        std::uint16_t machine = 0U;
        std::uint16_t sectionCount = 0U;
        std::uint16_t optionalHeaderBytes = 0U;
        const std::size_t fileHeaderOffset = static_cast<std::size_t>(peOffset) + 4U;
        const std::size_t optionalHeaderOffset = fileHeaderOffset + 20U;
        if (!driverModuleDumpReadValue(headerBytes, peOffset, peSignature) ||
            !driverModuleDumpReadValue(headerBytes, fileHeaderOffset, machine) ||
            !driverModuleDumpReadValue(headerBytes, fileHeaderOffset + 2U, sectionCount) ||
            !driverModuleDumpReadValue(headerBytes, fileHeaderOffset + 16U, optionalHeaderBytes) ||
            peSignature != 0x00004550U ||
            machine == 0U ||
            sectionCount == 0U ||
            sectionCount > 96U ||
            optionalHeaderBytes < 64U ||
            optionalHeaderOffset > headerBytes.size() ||
            optionalHeaderBytes > headerBytes.size() - optionalHeaderOffset)
        {
            technicalDetailOut = QString::fromLatin1(
                "Loaded image NT headers are invalid (PE=0x%1, machine=0x%2, "
                "sections=%3, optionalBytes=%4, e_lfanew=0x%5).")
                .arg(peSignature, 0, 16)
                .arg(machine, 0, 16)
                .arg(sectionCount)
                .arg(optionalHeaderBytes)
                .arg(peOffset, 0, 16);
            return false;
        }

        std::uint16_t optionalMagic = 0U;
        std::uint32_t sectionAlignment = 0U;
        std::uint32_t sizeOfImage = 0U;
        std::uint32_t sizeOfHeaders = 0U;
        if (!driverModuleDumpReadValue(headerBytes, optionalHeaderOffset, optionalMagic) ||
            !driverModuleDumpReadValue(headerBytes, optionalHeaderOffset + 32U, sectionAlignment) ||
            !driverModuleDumpReadValue(headerBytes, optionalHeaderOffset + 56U, sizeOfImage) ||
            !driverModuleDumpReadValue(headerBytes, optionalHeaderOffset + 60U, sizeOfHeaders) ||
            (optionalMagic != 0x10BU && optionalMagic != 0x20BU) ||
            sectionAlignment == 0U ||
            (sectionAlignment & (sectionAlignment - 1U)) != 0U ||
            sizeOfHeaders == 0U ||
            sizeOfHeaders > sizeOfImage ||
            sizeOfImage == 0U ||
            sizeOfImage > kDriverModuleDumpHardMaxBytes ||
            sizeOfImage % sectionAlignment != 0U ||
            sizeOfImage != authoritativeSize)
        {
            technicalDetailOut = QString::fromLatin1(
                "Loaded image SizeOfImage cross-check failed (magic=0x%1, "
                "alignment=%2, headers=%3, PE size=%4, R0 module size=%5).")
                .arg(optionalMagic, 0, 16)
                .arg(sectionAlignment)
                .arg(sizeOfHeaders)
                .arg(sizeOfImage)
                .arg(authoritativeSize);
            return false;
        }
        return true;
    }

    bool driverOperationHasUnsafeWin32PathSyntax(
        const QString& pathText,
        const bool allowUnc)
    {
        const QString nativePath =
            QDir::toNativeSeparators(pathText.trimmed());
        if (nativePath.isEmpty() ||
            nativePath.startsWith(QStringLiteral("\\\\?\\")) ||
            nativePath.startsWith(QStringLiteral("\\\\.\\")) ||
            nativePath.startsWith(QStringLiteral("\\??\\")) ||
            nativePath.startsWith(QStringLiteral("\\Device\\"), Qt::CaseInsensitive))
        {
            return true;
        }

        const QFileInfo pathInfo(nativePath);
        if (!pathInfo.isAbsolute())
        {
            return true;
        }

        QString pathWithoutRoot;
        if (nativePath.startsWith(QStringLiteral("\\\\")))
        {
            if (!allowUnc || nativePath.contains(QLatin1Char(':')))
            {
                return true;
            }
            pathWithoutRoot = nativePath.mid(2);
        }
        else
        {
            if (nativePath.size() < 3 ||
                !nativePath.at(0).isLetter() ||
                nativePath.at(1) != QLatin1Char(':') ||
                nativePath.at(2) != QLatin1Char('\\') ||
                nativePath.indexOf(QLatin1Char(':'), 2) >= 0)
            {
                return true;
            }
            pathWithoutRoot = nativePath.mid(2);
        }

        if (pathWithoutRoot.contains(
            QRegularExpression(QStringLiteral(R"([<>:"|?*\x00-\x1F])"))))
        {
            return true;
        }
        const QStringList pathParts =
            QDir::fromNativeSeparators(pathWithoutRoot)
                .split(QLatin1Char('/'), Qt::SkipEmptyParts);
        const QRegularExpression reservedDosNameExpression(
            QStringLiteral(R"(^(CON|PRN|AUX|NUL|CLOCK\$|COM[1-9]|LPT[1-9])$)"),
            QRegularExpression::CaseInsensitiveOption);
        for (const QString& pathPart : pathParts)
        {
            const int extensionSeparator = pathPart.indexOf(QLatin1Char('.'));
            const QString deviceStem =
                (extensionSeparator >= 0
                    ? pathPart.left(extensionSeparator)
                    : pathPart)
                .trimmed();
            if (pathPart.endsWith(QLatin1Char('.')) ||
                pathPart.endsWith(QLatin1Char(' ')) ||
                reservedDosNameExpression.match(deviceStem).hasMatch())
            {
                return true;
            }
        }
        return false;
    }

    QString driverModuleDumpPathIdentityKey(const QString& pathText)
    {
        const QFileInfo pathInfo(pathText);
        const QString canonicalPath = pathInfo.canonicalFilePath();
        const QString identityPath = canonicalPath.isEmpty()
            ? pathInfo.absoluteFilePath()
            : canonicalPath;
        if (identityPath.isEmpty())
        {
            return QString();
        }
        return QDir::toNativeSeparators(
            QDir::cleanPath(QDir::fromNativeSeparators(identityPath)))
            .toCaseFolded();
    }

    QString driverModuleDumpExtendedPath(const QString& pathText)
    {
        QString nativePath = QDir::toNativeSeparators(
            QFileInfo(pathText).absoluteFilePath());
        if (nativePath.startsWith(QStringLiteral("\\\\?\\")))
        {
            return nativePath;
        }
        if (nativePath.startsWith(QStringLiteral("\\\\")))
        {
            return QStringLiteral("\\\\?\\UNC\\") + nativePath.mid(2);
        }
        return QStringLiteral("\\\\?\\") + nativePath;
    }

    DriverModuleDumpResult driverModuleDumpToFile(
        const QString& ntPath,
        const std::uint64_t moduleBase,
        const QString& targetPath)
    {
        DriverModuleDumpResult dumpResult;
        dumpResult.targetPath = QFileInfo(targetPath).absoluteFilePath();
        dumpResult.moduleBase = moduleBase;
        if (moduleBase == 0U ||
            ntPath.isEmpty() ||
            dumpResult.targetPath.isEmpty() ||
            driverOperationHasUnsafeWin32PathSyntax(
                dumpResult.targetPath,
                true))
        {
            dumpResult.error = DriverModuleDumpError::InvalidTarget;
            dumpResult.technicalDetail = QString::fromLatin1("Module dump parameters are invalid.");
            return dumpResult;
        }
        if (QFileInfo::exists(dumpResult.targetPath))
        {
            dumpResult.error = DriverModuleDumpError::TargetExists;
            dumpResult.win32Error = ERROR_FILE_EXISTS;
            dumpResult.technicalDetail = QString::fromLatin1(
                "The destination already exists; overwrite is forbidden.");
            return dumpResult;
        }

        const ksword::ark::DriverClient driverClient;
        std::uint32_t moduleSize = 0U;
        if (!driverModuleDumpQueryIdentity(
            driverClient,
            ntPath,
            moduleBase,
            0U,
            moduleSize,
            dumpResult.technicalDetail))
        {
            dumpResult.error = DriverModuleDumpError::IdentityCheck;
            return dumpResult;
        }
        dumpResult.moduleSize = moduleSize;

        ksword::ark::DriverHandle driverHandle = driverClient.open();
        if (!driverHandle.isValid())
        {
            dumpResult.error = DriverModuleDumpError::DeviceOpen;
            dumpResult.win32Error = ::GetLastError();
            dumpResult.technicalDetail = QString::fromLatin1(
                "Opening the KswordARK R0 control device failed.");
            return dumpResult;
        }

        const std::uint32_t headerBytesToRead =
            std::min<std::uint32_t>(moduleSize, kDriverModuleDumpHeaderProbeBytes);
        if (headerBytesToRead < 256U)
        {
            dumpResult.error = DriverModuleDumpError::PeValidation;
            dumpResult.technicalDetail = QString::fromLatin1(
                "The authoritative module image size is too small for a PE image.");
            return dumpResult;
        }
        const ksword::ark::VirtualMemoryReadResult headerRead =
            driverClient.readVirtualMemory(
                0U,
                moduleBase,
                headerBytesToRead,
                KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS |
                    KSWORD_ARK_MEMORY_READ_FLAG_ZERO_FILL_UNREADABLE,
                &driverHandle);
        bool headerReadZeroFilled = false;
        if (!driverModuleDumpValidateRead(
            headerRead,
            moduleBase,
            headerBytesToRead,
            dumpResult.technicalDetail,
            headerReadZeroFilled))
        {
            dumpResult.error = DriverModuleDumpError::MemoryRead;
            return dumpResult;
        }
        if (headerReadZeroFilled)
        {
            ++dumpResult.zeroFilledChunkCount;
        }
        if (!driverModuleDumpValidatePeImage(
            headerRead.data,
            moduleSize,
            dumpResult.technicalDetail))
        {
            dumpResult.error = DriverModuleDumpError::PeValidation;
            return dumpResult;
        }

        const QFileInfo targetInfo(dumpResult.targetPath);
        QDir targetDirectory = targetInfo.dir();
        if (!targetDirectory.exists())
        {
            dumpResult.error = DriverModuleDumpError::DestinationDirectory;
            dumpResult.win32Error = ERROR_PATH_NOT_FOUND;
            dumpResult.technicalDetail = QString::fromLatin1(
                "The destination directory does not exist.");
            return dumpResult;
        }
        DriverModuleDumpFile temporaryFile;
        if (!temporaryFile.create(dumpResult.targetPath))
        {
            dumpResult.error =
                temporaryFile.error() == DriverModuleDumpFileError::TargetExists
                ? DriverModuleDumpError::TargetExists
                : DriverModuleDumpError::TemporaryFileCreate;
            dumpResult.win32Error = temporaryFile.win32Error();
            dumpResult.technicalDetail = temporaryFile.technicalDetail();
            return dumpResult;
        }

        const auto writeChunk =
            [&temporaryFile, &dumpResult](const std::vector<std::uint8_t>& bytes) -> bool
            {
                if (!temporaryFile.write(bytes.data(), bytes.size()))
                {
                    dumpResult.error = DriverModuleDumpError::TemporaryFileWrite;
                    dumpResult.win32Error = temporaryFile.win32Error();
                    dumpResult.technicalDetail = temporaryFile.technicalDetail();
                    return false;
                }
                return true;
            };
        if (!writeChunk(headerRead.data))
        {
            return dumpResult;
        }

        std::uint64_t offset = headerBytesToRead;
        while (offset < moduleSize)
        {
            const std::uint32_t chunkBytes = static_cast<std::uint32_t>(
                std::min<std::uint64_t>(
                    KSWORD_ARK_MEMORY_READ_MAX_BYTES,
                    static_cast<std::uint64_t>(moduleSize) - offset));
            const std::uint64_t chunkAddress = moduleBase + offset;
            const ksword::ark::VirtualMemoryReadResult readResult =
                driverClient.readVirtualMemory(
                    0U,
                    chunkAddress,
                    chunkBytes,
                    KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS |
                        KSWORD_ARK_MEMORY_READ_FLAG_ZERO_FILL_UNREADABLE,
                    &driverHandle);
            bool readZeroFilled = false;
            if (!driverModuleDumpValidateRead(
                readResult,
                chunkAddress,
                chunkBytes,
                dumpResult.technicalDetail,
                readZeroFilled))
            {
                dumpResult.error = DriverModuleDumpError::MemoryRead;
                return dumpResult;
            }
            if (readZeroFilled)
            {
                ++dumpResult.zeroFilledChunkCount;
            }
            if (!writeChunk(readResult.data))
            {
                return dumpResult;
            }
            offset += chunkBytes;
        }

        std::uint32_t finalModuleSize = 0U;
        if (!driverModuleDumpQueryIdentity(
            driverClient,
            ntPath,
            moduleBase,
            moduleSize,
            finalModuleSize,
            dumpResult.technicalDetail))
        {
            dumpResult.error = DriverModuleDumpError::IdentityCheck;
            dumpResult.technicalDetail.prepend(QString::fromLatin1(
                "Final loaded-module identity check failed. "));
            return dumpResult;
        }
        if (!temporaryFile.commit(moduleSize))
        {
            switch (temporaryFile.error())
            {
            case DriverModuleDumpFileError::Flush:
                dumpResult.error = DriverModuleDumpError::TemporaryFileFlush;
                break;
            case DriverModuleDumpFileError::TargetExists:
                dumpResult.error = DriverModuleDumpError::TargetExists;
                break;
            case DriverModuleDumpFileError::Commit:
            default:
                dumpResult.error = DriverModuleDumpError::AtomicCommit;
                break;
            }
            dumpResult.win32Error = temporaryFile.win32Error();
            dumpResult.technicalDetail = temporaryFile.technicalDetail();
            return dumpResult;
        }

        dumpResult.ok = true;
        return dumpResult;
    }

    enum class DriverScCleanupStage : std::uint32_t
    {
        TargetValidation = 0U,
        PreflightConfig,
        PreflightSharing,
        StopRequest,
        StopWait,
        PostflightConfig,
        PostflightSharing,
        ServiceDelete,
        FileDelete,
        Complete
    };

    struct DriverScCleanupResult
    {
        DriverScCleanupStage stage = DriverScCleanupStage::TargetValidation;
        bool ok = false;
        bool stopReached = false;
        bool serviceDeleted = false;
        bool fileDeletedOrMissing = false;
        bool fileWasMissing = false;
        std::uint32_t win32Error = 0U;
        std::uint32_t finalServiceState = 0U;
        QString normalizedPath;
        QString technicalDetail;
        QStringList sharedServiceNames;
    };

    struct DriverScCleanupFileIdentity
    {
        bool exists = false;
        std::uint32_t volumeSerialNumber = 0U;
        std::uint32_t fileIndexHigh = 0U;
        std::uint32_t fileIndexLow = 0U;
        QString finalPath;
    };

    QString driverScCleanupStageText(const DriverScCleanupStage stage)
    {
        switch (stage)
        {
        case DriverScCleanupStage::TargetValidation:
            return driverText(
                "driver.cleanup.stage.target_validation",
                QStringLiteral("目标校验"));
        case DriverScCleanupStage::PreflightConfig:
            return driverText(
                "driver.cleanup.stage.preflight_config",
                QStringLiteral("停止前服务配置复核"));
        case DriverScCleanupStage::PreflightSharing:
            return driverText(
                "driver.cleanup.stage.preflight_sharing",
                QStringLiteral("停止前共享路径复核"));
        case DriverScCleanupStage::StopRequest:
            return driverText(
                "driver.cleanup.stage.stop_request",
                QStringLiteral("SCM 停止请求"));
        case DriverScCleanupStage::StopWait:
            return driverText(
                "driver.cleanup.stage.stop_wait",
                QStringLiteral("等待 SERVICE_STOPPED"));
        case DriverScCleanupStage::PostflightConfig:
            return driverText(
                "driver.cleanup.stage.postflight_config",
                QStringLiteral("停止后服务配置复核"));
        case DriverScCleanupStage::PostflightSharing:
            return driverText(
                "driver.cleanup.stage.postflight_sharing",
                QStringLiteral("停止后共享路径复核"));
        case DriverScCleanupStage::ServiceDelete:
            return driverText(
                "driver.cleanup.stage.service_delete",
                QStringLiteral("删除服务注册"));
        case DriverScCleanupStage::FileDelete:
            return driverText(
                "driver.cleanup.stage.file_delete",
                QStringLiteral("删除驱动文件"));
        case DriverScCleanupStage::Complete:
            return driverText(
                "driver.cleanup.stage.complete",
                QStringLiteral("完成"));
        default:
            return driverText(
                "driver.cleanup.stage.unknown",
                QStringLiteral("未知阶段"));
        }
    }

    QString driverScCleanupWindowsDirectory()
    {
        std::vector<wchar_t> pathBuffer(32768U, L'\0');
        const UINT pathLength = ::GetWindowsDirectoryW(
            pathBuffer.data(),
            static_cast<UINT>(pathBuffer.size()));
        if (pathLength == 0U ||
            pathLength >= static_cast<UINT>(pathBuffer.size()))
        {
            return QString();
        }
        return QDir::toNativeSeparators(
            QString::fromWCharArray(pathBuffer.data(), static_cast<int>(pathLength)));
    }

    QString driverScCleanupNormalizePath(const QString& rawPathText)
    {
        QString pathText =
            ks::online_scan::normalizeKernelImagePathForUpload(rawPathText).trimmed();
        if (pathText.isEmpty() ||
            pathText.compare(QStringLiteral("<unknown>"), Qt::CaseInsensitive) == 0)
        {
            return QString();
        }

        pathText = QDir::toNativeSeparators(pathText);
        if (QFileInfo(pathText).isRelative())
        {
            const QString portablePath = QDir::fromNativeSeparators(pathText);
            if (!portablePath.startsWith(
                QStringLiteral("System32/"),
                Qt::CaseInsensitive))
            {
                return QString();
            }

            const QString windowsDirectory = driverScCleanupWindowsDirectory();
            if (windowsDirectory.isEmpty())
            {
                return QString();
            }
            pathText = QDir::toNativeSeparators(
                windowsDirectory + QLatin1Char('/') + portablePath);
        }

        pathText = QDir::toNativeSeparators(
            QDir::cleanPath(QDir::fromNativeSeparators(pathText)));
        const QFileInfo pathInfo(pathText);
        if (!pathInfo.isAbsolute() ||
            pathInfo.suffix().compare(QStringLiteral("sys"), Qt::CaseInsensitive) != 0 ||
            (pathInfo.exists() && !pathInfo.isFile()))
        {
            return QString();
        }
        const QString absolutePath =
            QDir::toNativeSeparators(pathInfo.absoluteFilePath());
        if (driverOperationHasUnsafeWin32PathSyntax(absolutePath, false))
        {
            return QString();
        }
        return absolutePath;
    }

    QString driverScCleanupPathIdentityKey(const QString& normalizedPath)
    {
        const QFileInfo pathInfo(normalizedPath);
        const QString canonicalPath = pathInfo.canonicalFilePath();
        const QString identityPath =
            canonicalPath.isEmpty() ? normalizedPath : canonicalPath;
        return QDir::toNativeSeparators(
            QDir::cleanPath(QDir::fromNativeSeparators(identityPath)))
            .toCaseFolded();
    }

    bool driverScCleanupQueryFileIdentity(
        const QString& normalizedPath,
        const DWORD desiredAccess,
        DriverScCleanupFileIdentity& identityOut,
        HANDLE* const handleOut,
        std::uint32_t& win32ErrorOut,
        QString& technicalDetailOut)
    {
        identityOut = DriverScCleanupFileIdentity{};
        win32ErrorOut = ERROR_SUCCESS;
        if (handleOut != nullptr)
        {
            *handleOut = INVALID_HANDLE_VALUE;
        }

        if (driverOperationHasUnsafeWin32PathSyntax(normalizedPath, false))
        {
            win32ErrorOut = ERROR_INVALID_NAME;
            technicalDetailOut = QString::fromLatin1(
                "The driver path contains unsafe Win32 path syntax.");
            return false;
        }

        const QString extendedPath =
            driverModuleDumpExtendedPath(normalizedPath);
        HANDLE fileHandle = ::CreateFileW(
            reinterpret_cast<LPCWSTR>(extendedPath.utf16()),
            desiredAccess,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            const DWORD openError = ::GetLastError();
            if (openError == ERROR_FILE_NOT_FOUND ||
                openError == ERROR_PATH_NOT_FOUND)
            {
                return true;
            }
            win32ErrorOut = openError;
            technicalDetailOut = QString::fromLatin1(
                "Opening the driver path for identity verification failed.");
            return false;
        }

        BY_HANDLE_FILE_INFORMATION fileInformation{};
        if (!::GetFileInformationByHandle(fileHandle, &fileInformation))
        {
            win32ErrorOut = ::GetLastError();
            technicalDetailOut = QString::fromLatin1(
                "GetFileInformationByHandle failed for the driver path.");
            ::CloseHandle(fileHandle);
            return false;
        }
        if ((fileInformation.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U)
        {
            win32ErrorOut = ERROR_REPARSE_POINT_ENCOUNTERED;
            technicalDetailOut = QString::fromLatin1(
                "The driver path ends at a reparse point; cleanup was refused.");
            ::CloseHandle(fileHandle);
            return false;
        }

        std::vector<wchar_t> finalPathBuffer(32768U, L'\0');
        const DWORD finalPathLength = ::GetFinalPathNameByHandleW(
            fileHandle,
            finalPathBuffer.data(),
            static_cast<DWORD>(finalPathBuffer.size()),
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (finalPathLength == 0U ||
            finalPathLength >= static_cast<DWORD>(finalPathBuffer.size()))
        {
            win32ErrorOut = finalPathLength == 0U
                ? ::GetLastError()
                : ERROR_INSUFFICIENT_BUFFER;
            technicalDetailOut = QString::fromLatin1(
                "GetFinalPathNameByHandleW failed for the driver path.");
            ::CloseHandle(fileHandle);
            return false;
        }

        identityOut.exists = true;
        identityOut.volumeSerialNumber = fileInformation.dwVolumeSerialNumber;
        identityOut.fileIndexHigh = fileInformation.nFileIndexHigh;
        identityOut.fileIndexLow = fileInformation.nFileIndexLow;
        identityOut.finalPath = QDir::toNativeSeparators(
            QString::fromWCharArray(
                finalPathBuffer.data(),
                static_cast<int>(finalPathLength)));
        if (handleOut != nullptr)
        {
            *handleOut = fileHandle;
        }
        else
        {
            ::CloseHandle(fileHandle);
        }
        return true;
    }

    bool driverScCleanupSameFileIdentity(
        const DriverScCleanupFileIdentity& left,
        const DriverScCleanupFileIdentity& right)
    {
        if (left.exists != right.exists)
        {
            return false;
        }
        if (!left.exists)
        {
            return true;
        }
        return left.volumeSerialNumber == right.volumeSerialNumber &&
            left.fileIndexHigh == right.fileIndexHigh &&
            left.fileIndexLow == right.fileIndexLow &&
            left.finalPath.compare(right.finalPath, Qt::CaseInsensitive) == 0;
    }

    bool driverScCleanupValidateLiveTarget(
        const std::wstring& serviceName,
        const QString& expectedNormalizedPath,
        const bool afterStop,
        DriverScCleanupResult& result)
    {
        result.stage = afterStop
            ? DriverScCleanupStage::PostflightConfig
            : DriverScCleanupStage::PreflightConfig;

        ks::service::ServiceRecord liveRecord;
        std::string serviceErrorText;
        std::uint32_t serviceErrorCode = 0U;
        if (!ks::service::QueryServiceRecord(
            serviceName,
            &liveRecord,
            &serviceErrorText,
            &serviceErrorCode))
        {
            result.win32Error = serviceErrorCode;
            result.technicalDetail = QString::fromUtf8(serviceErrorText.c_str());
            return false;
        }
        if (!liveRecord.hasConfig ||
            (liveRecord.config.serviceType & SERVICE_DRIVER) == 0U)
        {
            result.win32Error = ERROR_INVALID_DATA;
            result.technicalDetail = QString::fromLatin1(
                "The live SCM record is not a queryable driver service.");
            return false;
        }
        if (afterStop &&
            (!liveRecord.hasStatus ||
             liveRecord.status.currentState != SERVICE_STOPPED))
        {
            result.win32Error = ERROR_BUSY;
            result.finalServiceState = liveRecord.hasStatus
                ? liveRecord.status.currentState
                : 0U;
            result.technicalDetail = QString::fromLatin1(
                "The live SCM service state is no longer SERVICE_STOPPED (hasStatus=%1, currentState=%2).")
                .arg(liveRecord.hasStatus ? 1 : 0)
                .arg(result.finalServiceState);
            return false;
        }

        const QString currentPath = driverScCleanupNormalizePath(
            QString::fromStdWString(liveRecord.config.binaryPath));
        if (currentPath.isEmpty())
        {
            result.win32Error = ERROR_INVALID_DATA;
            result.technicalDetail = QString::fromLatin1(
                "The live SCM ImagePath is empty, relative, non-.sys, or otherwise unsafe.");
            return false;
        }
        if (currentPath.compare(expectedNormalizedPath, Qt::CaseInsensitive) != 0)
        {
            result.win32Error = ERROR_INVALID_DATA;
            result.technicalDetail = QString::fromLatin1(
                "The live SCM ImagePath changed after confirmation (expected=%1, current=%2).")
                .arg(expectedNormalizedPath, currentPath);
            return false;
        }
        result.normalizedPath = currentPath;

        result.stage = afterStop
            ? DriverScCleanupStage::PostflightSharing
            : DriverScCleanupStage::PreflightSharing;
        std::vector<ks::service::ServiceRecord> serviceRecords;
        std::string enumerationErrorText;
        std::uint32_t enumerationErrorCode = 0U;
        if (!ks::service::EnumerateServiceRecords(
            SERVICE_DRIVER,
            SERVICE_STATE_ALL,
            &serviceRecords,
            &enumerationErrorText,
            &enumerationErrorCode))
        {
            result.win32Error = enumerationErrorCode;
            result.technicalDetail = QString::fromUtf8(enumerationErrorText.c_str());
            return false;
        }

        const QString expectedPathKey =
            driverScCleanupPathIdentityKey(expectedNormalizedPath);
        if (expectedPathKey.isEmpty())
        {
            result.win32Error = ERROR_INVALID_DATA;
            result.technicalDetail = QString::fromLatin1(
                "The confirmed driver path has no stable comparison key.");
            return false;
        }
        DriverScCleanupFileIdentity expectedFileIdentity;
        std::uint32_t identityError = ERROR_SUCCESS;
        QString identityDetail;
        if (!driverScCleanupQueryFileIdentity(
            expectedNormalizedPath,
            FILE_READ_ATTRIBUTES,
            expectedFileIdentity,
            nullptr,
            identityError,
            identityDetail))
        {
            result.win32Error = identityError;
            result.technicalDetail = identityDetail;
            return false;
        }

        const QString serviceNameText = QString::fromStdWString(serviceName);
        QStringList sharedServiceNames;
        for (const ks::service::ServiceRecord& serviceRecord : serviceRecords)
        {
            const QString candidateServiceName =
                QString::fromStdWString(serviceRecord.serviceName).trimmed();
            if (candidateServiceName.compare(
                serviceNameText,
                Qt::CaseInsensitive) == 0)
            {
                continue;
            }
            if (!serviceRecord.hasConfig)
            {
                result.win32Error = ERROR_ACCESS_DENIED;
                result.technicalDetail = QString::fromLatin1(
                    "The driver target cannot be proven unshared because SCM config "
                    "is unavailable for service %1: %2")
                    .arg(
                        candidateServiceName,
                        QString::fromUtf8(serviceRecord.configErrorText.c_str()));
                return false;
            }

            const QString rawCandidatePath =
                QString::fromStdWString(serviceRecord.config.binaryPath).trimmed();
            if (rawCandidatePath.isEmpty())
            {
                continue;
            }
            const QString candidatePath =
                driverScCleanupNormalizePath(rawCandidatePath);
            if (candidatePath.isEmpty())
            {
                result.win32Error = ERROR_INVALID_DATA;
                result.technicalDetail = QString::fromLatin1(
                    "The driver target cannot be proven unshared because service %1 "
                    "has an unresolvable ImagePath: %2")
                    .arg(candidateServiceName, rawCandidatePath);
                return false;
            }
            DriverScCleanupFileIdentity candidateFileIdentity;
            identityError = ERROR_SUCCESS;
            identityDetail.clear();
            if (!driverScCleanupQueryFileIdentity(
                candidatePath,
                FILE_READ_ATTRIBUTES,
                candidateFileIdentity,
                nullptr,
                identityError,
                identityDetail))
            {
                result.win32Error = identityError;
                result.technicalDetail = QString::fromLatin1(
                    "The driver target cannot be proven unshared because the file identity for service %1 could not be queried.")
                    .arg(candidateServiceName);
                return false;
            }
            const bool sameExistingFile =
                expectedFileIdentity.exists &&
                candidateFileIdentity.exists &&
                expectedFileIdentity.volumeSerialNumber ==
                    candidateFileIdentity.volumeSerialNumber &&
                expectedFileIdentity.fileIndexHigh ==
                    candidateFileIdentity.fileIndexHigh &&
                expectedFileIdentity.fileIndexLow ==
                    candidateFileIdentity.fileIndexLow;
            if (driverScCleanupPathIdentityKey(candidatePath) == expectedPathKey ||
                sameExistingFile)
            {
                sharedServiceNames.push_back(candidateServiceName);
            }
        }
        if (!sharedServiceNames.isEmpty())
        {
            sharedServiceNames.sort(Qt::CaseInsensitive);
            result.sharedServiceNames = sharedServiceNames;
            result.win32Error = ERROR_SHARING_VIOLATION;
            result.technicalDetail = QString::fromLatin1(
                "The same driver file is referenced by other SCM services: %1")
                .arg(sharedServiceNames.join(QStringLiteral(", ")));
            return false;
        }
        return true;
    }

    DriverScCleanupResult driverScUnloadAndCleanup(
        const QString& serviceNameText,
        const QString& expectedNormalizedPath)
    {
        DriverScCleanupResult result;
        result.normalizedPath =
            driverScCleanupNormalizePath(expectedNormalizedPath);
        if (serviceNameText.trimmed().isEmpty() ||
            result.normalizedPath.isEmpty() ||
            result.normalizedPath.compare(
                expectedNormalizedPath,
                Qt::CaseInsensitive) != 0)
        {
            result.win32Error = ERROR_INVALID_PARAMETER;
            result.technicalDetail = QString::fromLatin1(
                "The immutable service name or confirmed driver path is invalid.");
            return result;
        }

        const std::wstring serviceName = toWideString(serviceNameText);
        if (!driverScCleanupValidateLiveTarget(
            serviceName,
            result.normalizedPath,
            false,
            result))
        {
            return result;
        }

        DriverScCleanupFileIdentity confirmedFileIdentity;
        std::uint32_t fileIdentityError = ERROR_SUCCESS;
        QString fileIdentityDetail;
        if (!driverScCleanupQueryFileIdentity(
            result.normalizedPath,
            FILE_READ_ATTRIBUTES,
            confirmedFileIdentity,
            nullptr,
            fileIdentityError,
            fileIdentityDetail))
        {
            result.stage = DriverScCleanupStage::PreflightConfig;
            result.win32Error = fileIdentityError;
            result.technicalDetail = fileIdentityDetail;
            return result;
        }

        result.stage = DriverScCleanupStage::StopRequest;
        ks::service::ServiceStatus finalStatus{};
        std::string stopErrorText;
        std::uint32_t stopErrorCode = 0U;
        const bool stopOk = ks::service::StopServiceByName(
            serviceName,
            10000U,
            SERVICE_STOPPED,
            &finalStatus,
            &stopErrorText,
            &stopErrorCode);
        result.finalServiceState = finalStatus.currentState;
        if (!stopOk)
        {
            result.win32Error = stopErrorCode;
            result.technicalDetail = QString::fromUtf8(stopErrorText.c_str());
            return result;
        }
        if (finalStatus.currentState != SERVICE_STOPPED)
        {
            result.stage = DriverScCleanupStage::StopWait;
            result.win32Error = ERROR_TIMEOUT;
            result.technicalDetail = QString::fromLatin1(
                "StopServiceByName returned without reaching SERVICE_STOPPED "
                "(finalState=%1).")
                .arg(finalStatus.currentState);
            return result;
        }
        result.stopReached = true;

        if (!driverScCleanupValidateLiveTarget(
            serviceName,
            result.normalizedPath,
            true,
            result))
        {
            return result;
        }

        DriverScCleanupFileIdentity postStopFileIdentity;
        fileIdentityError = ERROR_SUCCESS;
        fileIdentityDetail.clear();
        if (!driverScCleanupQueryFileIdentity(
            result.normalizedPath,
            FILE_READ_ATTRIBUTES,
            postStopFileIdentity,
            nullptr,
            fileIdentityError,
            fileIdentityDetail))
        {
            result.stage = DriverScCleanupStage::PostflightConfig;
            result.win32Error = fileIdentityError;
            result.technicalDetail = fileIdentityDetail;
            return result;
        }
        if (postStopFileIdentity.exists &&
            !driverScCleanupSameFileIdentity(
                confirmedFileIdentity,
                postStopFileIdentity))
        {
            result.stage = DriverScCleanupStage::PostflightConfig;
            result.win32Error = ERROR_FILE_INVALID;
            result.technicalDetail = QString::fromLatin1(
                "The driver file identity changed while the service was stopping.");
            return result;
        }
        confirmedFileIdentity = postStopFileIdentity;

        // 把状态、配置路径和共享引用的最终复核尽量贴近 DeleteService，
        // 避免 STOPPED 后被其它进程重新启动或重新绑定路径时继续清理。
        if (!driverScCleanupValidateLiveTarget(
            serviceName,
            result.normalizedPath,
            true,
            result))
        {
            return result;
        }
        DriverScCleanupFileIdentity deleteGateFileIdentity;
        fileIdentityError = ERROR_SUCCESS;
        fileIdentityDetail.clear();
        if (!driverScCleanupQueryFileIdentity(
            result.normalizedPath,
            FILE_READ_ATTRIBUTES,
            deleteGateFileIdentity,
            nullptr,
            fileIdentityError,
            fileIdentityDetail))
        {
            result.stage = DriverScCleanupStage::PostflightConfig;
            result.win32Error = fileIdentityError;
            result.technicalDetail = fileIdentityDetail;
            return result;
        }
        if (deleteGateFileIdentity.exists &&
            !driverScCleanupSameFileIdentity(
                confirmedFileIdentity,
                deleteGateFileIdentity))
        {
            result.stage = DriverScCleanupStage::PostflightConfig;
            result.win32Error = ERROR_FILE_INVALID;
            result.technicalDetail = QString::fromLatin1(
                "The driver file identity changed immediately before service deletion.");
            return result;
        }
        confirmedFileIdentity = deleteGateFileIdentity;

        result.stage = DriverScCleanupStage::ServiceDelete;
        std::string deleteServiceErrorText;
        std::uint32_t deleteServiceErrorCode = 0U;
        if (!ks::service::DeleteServiceByName(
            serviceName,
            false,
            0U,
            &deleteServiceErrorText,
            &deleteServiceErrorCode))
        {
            result.win32Error = deleteServiceErrorCode;
            result.technicalDetail =
                QString::fromUtf8(deleteServiceErrorText.c_str());
            return result;
        }
        result.finalServiceState = SERVICE_STOPPED;
        result.serviceDeleted = true;

        result.stage = DriverScCleanupStage::FileDelete;
        DriverScCleanupFileIdentity deleteFileIdentity;
        HANDLE deleteFileHandle = INVALID_HANDLE_VALUE;
        fileIdentityError = ERROR_SUCCESS;
        fileIdentityDetail.clear();
        if (!driverScCleanupQueryFileIdentity(
            result.normalizedPath,
            DELETE | FILE_READ_ATTRIBUTES,
            deleteFileIdentity,
            &deleteFileHandle,
            fileIdentityError,
            fileIdentityDetail))
        {
            result.win32Error = fileIdentityError;
            result.technicalDetail = fileIdentityDetail;
            return result;
        }
        if (!deleteFileIdentity.exists)
        {
            result.fileWasMissing = true;
        }
        else
        {
            if (!driverScCleanupSameFileIdentity(
                confirmedFileIdentity,
                deleteFileIdentity))
            {
                ::CloseHandle(deleteFileHandle);
                result.win32Error = ERROR_FILE_INVALID;
                result.technicalDetail = QString::fromLatin1(
                    "The driver path now refers to a different file; deletion was refused.");
                return result;
            }

            FILE_DISPOSITION_INFO dispositionInformation{};
            dispositionInformation.DeleteFile = TRUE;
            if (!::SetFileInformationByHandle(
                deleteFileHandle,
                FileDispositionInfo,
                &dispositionInformation,
                sizeof(dispositionInformation)))
            {
                result.win32Error = ::GetLastError();
                result.technicalDetail = QString::fromLatin1(
                    "Deleting the identity-verified driver file failed after the service registration was deleted.");
                ::CloseHandle(deleteFileHandle);
                return result;
            }
            ::CloseHandle(deleteFileHandle);
        }
        result.fileDeletedOrMissing = true;
        result.stage = DriverScCleanupStage::Complete;
        result.ok = true;
        result.win32Error = ERROR_SUCCESS;
        result.technicalDetail.clear();
        return result;
    }

    // DriverDock 后台刷新/SCM 操作的实例级状态属性名：
    // - 作用：服务列表刷新、模块列表刷新与挂载/卸载/删除都改为线程池执行后，
    //   需要按 DriverDock 实例记录“最新一次请求票据”和“SCM 操作进行中”标记；
    // - 承载方式：不新增 DriverDock 头文件成员，改用 QObject 动态属性，随实例析构自动释放；
    // - 线程约束：只在 UI 线程读写（请求下发与结果回投都发生在 UI 线程），无需额外加锁。
    constexpr const char* kDriverServiceRefreshTicketProperty = "kswordDriverServiceRefreshTicket";
    constexpr const char* kLoadedModuleRefreshTicketProperty = "kswordLoadedModuleRefreshTicket";
    constexpr const char* kDriverServiceControlBusyProperty = "kswordDriverServiceControlBusy";

    quint64 allocateDriverDockRefreshTicket(
        QObject* ticketOwnerObject,
        const char* ticketPropertyName)
    {
        // allocateDriverDockRefreshTicket：
        // - 入参：承载票据的 DriverDock 实例、动态属性名；
        // - 处理：在 UI 线程把票据自增一次并写回动态属性；
        // - 返回：本次后台请求应携带的票据值。
        if (ticketOwnerObject == nullptr)
        {
            return 0U;
        }
        const quint64 nextTicketValue =
            static_cast<quint64>(ticketOwnerObject->property(ticketPropertyName).toULongLong()) + 1U;
        ticketOwnerObject->setProperty(ticketPropertyName, QVariant::fromValue(nextTicketValue));
        return nextTicketValue;
    }

    bool isDriverDockRefreshTicketCurrent(
        const QObject* ticketOwnerObject,
        const char* ticketPropertyName,
        const quint64 requestTicketValue)
    {
        // isDriverDockRefreshTicketCurrent：
        // - 入参：承载票据的 DriverDock 实例、动态属性名、后台任务携带的请求票据；
        // - 处理：与动态属性里的最新票据比较，识别已被新请求取代的旧结果；
        // - 返回：true 表示结果仍然有效，false 表示应直接丢弃。
        if (ticketOwnerObject == nullptr)
        {
            return false;
        }
        return static_cast<quint64>(
            ticketOwnerObject->property(ticketPropertyName).toULongLong()) == requestTicketValue;
    }

    bool tryBeginDriverServiceControlOperation(QObject* controlOwnerObject)
    {
        // tryBeginDriverServiceControlOperation：
        // - 入参：发起挂载/卸载/删除的 DriverDock 实例；
        // - 处理：检查并置位“SCM 操作进行中”标记，避免同一目标服务被并发下发多次控制请求；
        // - 返回：true 表示本次请求可以下发，false 表示已有同类操作在跑。
        if (controlOwnerObject == nullptr)
        {
            return false;
        }
        if (controlOwnerObject->property(kDriverServiceControlBusyProperty).toBool())
        {
            return false;
        }
        controlOwnerObject->setProperty(kDriverServiceControlBusyProperty, true);
        return true;
    }

    void endDriverServiceControlOperation(QObject* controlOwnerObject)
    {
        // endDriverServiceControlOperation：
        // - 入参：发起挂载/卸载/删除的 DriverDock 实例；
        // - 处理：清除“SCM 操作进行中”标记，允许下一次控制请求；
        // - 返回：无。
        if (controlOwnerObject == nullptr)
        {
            return;
        }
        controlOwnerObject->setProperty(kDriverServiceControlBusyProperty, false);
    }

    void setDriverServiceControlButtonsEnabled(
        QPushButton* loadDriverButton,
        QPushButton* unloadDriverButton,
        QPushButton* deleteServiceButton,
        const bool enabledState)
    {
        // setDriverServiceControlButtonsEnabled：
        // - 入参：挂载/卸载/删除三个按钮指针与目标可用状态；
        // - 处理：逐个判空后设置 enabled，让后台 SCM 操作期间的“进行中”状态对用户可见；
        // - 返回：无。
        if (loadDriverButton != nullptr)
        {
            loadDriverButton->setEnabled(enabledState);
        }
        if (unloadDriverButton != nullptr)
        {
            unloadDriverButton->setEnabled(enabledState);
        }
        if (deleteServiceButton != nullptr)
        {
            deleteServiceButton->setEnabled(enabledState);
        }
    }

}

void DriverDock::refreshDriverServiceRecords()
{
    // 驱动服务列表刷新：
    // - 入参：无；过滤条件仍由服务表自身的过滤器承担；
    // - 处理：SCM 全量枚举与逐条 QueryServiceConfig 搬到线程池执行，UI 线程只负责结果落地；
    // - 返回：无返回值；结果通过服务表与概览状态标签体现，过期票据的快照会被丢弃。
    const QPointer<DriverDock> guardThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("driver-service-record-refresh"),
        { m_serviceTable, m_moduleTable },
        [guardThis]()
        {
            if (!guardThis.isNull())
            {
                guardThis->refreshDriverServiceRecords();
            }
        }))
    {
        return;
    }

    kLogEvent refreshEvent;
    info << refreshEvent
        << driverText("driver.log.refresh_services_start", QStringLiteral("[DriverDock] 开始刷新驱动服务列表。"))
        << eol;

    // 刷新票据：刷新按钮连点、挂载/卸载/删除后的连带刷新都可能并发下发采集，
    // 只有最后一次请求的结果允许落地，避免旧快照覆盖新快照。
    const quint64 requestTicket =
        allocateDriverDockRefreshTicket(this, kDriverServiceRefreshTicketProperty);

    QRunnable* collectServiceTask = QRunnable::create(
        [guardThis, requestTicket, refreshEvent]()
        {
            // 后台线程只做纯数据采集：queryDriverServiceRecords 是静态成员函数，
            // 只访问 SCM 并产出值类型记录，不触碰任何 QWidget。
            std::vector<DriverServiceRecord> collectedServiceRecords;
            std::string collectErrorText;
            const bool collectSucceeded = DriverDock::queryDriverServiceRecords(
                collectedServiceRecords,
                &collectErrorText);

            // 回投使用长生命周期的 QCoreApplication 作为 receiver，并在 UI 线程重新校验 QPointer，
            // 这样 DriverDock 在采集期间析构时不会把悬垂指针传给 invokeMethod。
            QCoreApplication* const applicationInstance = QCoreApplication::instance();
            if (applicationInstance == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                applicationInstance,
                [guardThis,
                 requestTicket,
                 refreshEvent,
                 collectSucceeded,
                 collectedServiceRecords = std::move(collectedServiceRecords),
                 collectErrorText]() mutable
                {
                    if (guardThis.isNull())
                    {
                        return;
                    }
                    if (!isDriverDockRefreshTicketCurrent(
                        guardThis.data(),
                        kDriverServiceRefreshTicketProperty,
                        requestTicket))
                    {
                        return;
                    }

                    // 采集期间用户可能打开右键菜单：此时丢弃本次快照，
                    // 菜单关闭后由屏障回投重新发起一次完整刷新，避免菜单依赖的行索引被重建打乱。
                    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                        guardThis.data(),
                        QStringLiteral("driver-service-record-refresh"),
                        { guardThis->m_serviceTable, guardThis->m_moduleTable },
                        [guardThis]()
                        {
                            if (!guardThis.isNull())
                            {
                                guardThis->refreshDriverServiceRecords();
                            }
                        }))
                    {
                        return;
                    }

                    if (!collectSucceeded)
                    {
                        guardThis->m_driverServiceCache.clear();
                        guardThis->rebuildDriverServiceTableByFilter();
                        guardThis->appendOperateLogLine(
                            driverText(
                                "driver.operation.refresh.service_failed",
                                QStringLiteral("刷新服务失败：%1"))
                            .arg(QString::fromUtf8(collectErrorText.c_str())));
                        if (guardThis->m_overviewStatusLabel != nullptr)
                        {
                            guardThis->m_overviewStatusLabel->setText(
                                driverText(
                                    "driver.operation.refresh.service_failed_status",
                                    QStringLiteral("状态：服务刷新失败（%1）"))
                                .arg(QString::fromUtf8(collectErrorText.c_str())));
                        }
                        warn << refreshEvent
                            << driverText(
                                "driver.log.refresh_services_failed",
                                QStringLiteral("[DriverDock] 刷新服务失败, detail="))
                            << collectErrorText << eol;
                        return;
                    }

                    guardThis->m_driverServiceCache = std::move(collectedServiceRecords);
                    guardThis->rebuildDriverServiceTableByFilter();

                    if (guardThis->m_overviewStatusLabel != nullptr)
                    {
                        guardThis->m_overviewStatusLabel->setText(
                            driverText(
                                "driver.overview.count.filtered",
                                QStringLiteral("状态：驱动服务 %1 条（显示 %2 条），模块 %3 条（显示 %4 条）"))
                            .arg(guardThis->m_driverServiceCache.size())
                            .arg(guardThis->m_serviceTable != nullptr ? guardThis->m_serviceTable->rowCount() : 0)
                            .arg(guardThis->m_loadedModuleCache.size())
                            .arg(guardThis->m_moduleTable != nullptr ? guardThis->m_moduleTable->rowCount() : 0));
                    }

                    info << refreshEvent
                        << driverText(
                            "driver.log.refresh_services_completed",
                            QStringLiteral("[DriverDock] 刷新服务完成, count="))
                        << guardThis->m_driverServiceCache.size() << eol;
                },
                Qt::QueuedConnection);
        });
    collectServiceTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(collectServiceTask);
}

void DriverDock::refreshLoadedKernelModuleRecords()
{
    // 已加载内核模块列表刷新：
    // - 入参：无；
    // - 处理：EnumDeviceDrivers 与逐模块 GetDeviceDriverBaseNameW/GetDeviceDriverFileNameW
    //   搬到线程池执行，UI 线程只负责结果落地并接续模块证据聚合；
    // - 返回：无返回值；结果通过模块表与概览状态标签体现，过期票据的快照会被丢弃。
    const QPointer<DriverDock> guardThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("driver-loaded-module-refresh"),
        { m_serviceTable, m_moduleTable },
        [guardThis]()
        {
            if (!guardThis.isNull())
            {
                guardThis->refreshLoadedKernelModuleRecords();
            }
        }))
    {
        return;
    }

    kLogEvent refreshEvent;
    info << refreshEvent
        << driverText("driver.log.refresh_modules_start", QStringLiteral("[DriverDock] 开始刷新已加载模块列表。"))
        << eol;

    // 刷新票据：与服务列表同理，模块刷新按钮连点或操作后的连带刷新只保留最后一次结果。
    const quint64 requestTicket =
        allocateDriverDockRefreshTicket(this, kLoadedModuleRefreshTicketProperty);

    QRunnable* collectModuleTask = QRunnable::create(
        [guardThis, requestTicket, refreshEvent]()
        {
            // 后台线程只做纯数据采集：queryLoadedKernelModuleRecords 是静态成员函数，
            // 只访问 psapi 并产出值类型记录，不触碰任何 QWidget。
            std::vector<LoadedKernelModuleRecord> collectedModuleRecords;
            std::string collectErrorText;
            const bool collectSucceeded = DriverDock::queryLoadedKernelModuleRecords(
                collectedModuleRecords,
                &collectErrorText);

            QCoreApplication* const applicationInstance = QCoreApplication::instance();
            if (applicationInstance == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                applicationInstance,
                [guardThis,
                 requestTicket,
                 refreshEvent,
                 collectSucceeded,
                 collectedModuleRecords = std::move(collectedModuleRecords),
                 collectErrorText]() mutable
                {
                    if (guardThis.isNull())
                    {
                        return;
                    }
                    if (!isDriverDockRefreshTicketCurrent(
                        guardThis.data(),
                        kLoadedModuleRefreshTicketProperty,
                        requestTicket))
                    {
                        return;
                    }

                    // 采集期间用户可能打开右键菜单：此时丢弃本次快照，菜单关闭后重新发起完整刷新。
                    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                        guardThis.data(),
                        QStringLiteral("driver-loaded-module-refresh"),
                        { guardThis->m_serviceTable, guardThis->m_moduleTable },
                        [guardThis]()
                        {
                            if (!guardThis.isNull())
                            {
                                guardThis->refreshLoadedKernelModuleRecords();
                            }
                        }))
                    {
                        return;
                    }

                    if (!collectSucceeded)
                    {
                        ++guardThis->m_moduleEvidenceQueryTicket;
                        guardThis->m_moduleEvidenceQuerying = false;
                        if (guardThis->m_refreshModuleEvidenceButton != nullptr)
                        {
                            guardThis->m_refreshModuleEvidenceButton->setEnabled(true);
                        }
                        guardThis->m_loadedModuleCache.clear();
                        guardThis->m_loadedModuleEvidenceCache.clear();
                        guardThis->rebuildLoadedModuleTable();
                        guardThis->appendOperateLogLine(
                            driverText(
                                "driver.operation.refresh.module_failed",
                                QStringLiteral("刷新模块失败：%1"))
                            .arg(QString::fromUtf8(collectErrorText.c_str())));
                        if (guardThis->m_overviewStatusLabel != nullptr)
                        {
                            guardThis->m_overviewStatusLabel->setText(
                                driverText(
                                    "driver.operation.refresh.module_failed_status",
                                    QStringLiteral("状态：模块刷新失败（%1）"))
                                .arg(QString::fromUtf8(collectErrorText.c_str())));
                        }
                        warn << refreshEvent
                            << driverText(
                                "driver.log.refresh_modules_failed",
                                QStringLiteral("[DriverDock] 刷新模块失败, detail="))
                            << collectErrorText << eol;
                        return;
                    }

                    ++guardThis->m_moduleEvidenceQueryTicket;
                    guardThis->m_moduleEvidenceQuerying = false;
                    if (guardThis->m_refreshModuleEvidenceButton != nullptr)
                    {
                        guardThis->m_refreshModuleEvidenceButton->setEnabled(true);
                    }

                    guardThis->m_loadedModuleCache = std::move(collectedModuleRecords);
                    guardThis->m_loadedModuleEvidenceCache.clear();
                    guardThis->m_loadedModuleEvidenceCache.reserve(guardThis->m_loadedModuleCache.size());
                    for (const LoadedKernelModuleRecord& moduleRecord : guardThis->m_loadedModuleCache)
                    {
                        guardThis->m_loadedModuleEvidenceCache.push_back(
                            DriverDock::buildPendingModuleEvidenceRecord(moduleRecord));
                    }
                    guardThis->rebuildLoadedModuleTable();

                    if (guardThis->m_overviewStatusLabel != nullptr)
                    {
                        guardThis->m_overviewStatusLabel->setText(
                            driverText(
                                "driver.overview.count.filtered",
                                QStringLiteral("状态：驱动服务 %1 条（显示 %2 条），模块 %3 条（显示 %4 条）"))
                            .arg(guardThis->m_driverServiceCache.size())
                            .arg(guardThis->m_serviceTable != nullptr ? guardThis->m_serviceTable->rowCount() : 0)
                            .arg(guardThis->m_loadedModuleCache.size())
                            .arg(guardThis->m_moduleTable != nullptr ? guardThis->m_moduleTable->rowCount() : 0));
                    }
                    if (guardThis->m_moduleEvidenceStatusLabel != nullptr)
                    {
                        guardThis->m_moduleEvidenceStatusLabel->setText(
                            driverText(
                                "driver.evidence.status.modules_refreshed",
                                QStringLiteral("证据：模块列表已刷新。")));
                    }
                    if (!guardThis->m_loadedModuleCache.empty())
                    {
                        // 模块证据聚合只在已有模块快照时启动：
                        // - 输入：当前 EnumDeviceDrivers 枚举出的模块缓存；
                        // - 处理：交给后台线程调用现有 ArkDriverClient 只读接口；
                        // - 返回：无；空列表直接停留在提示状态，避免刷新函数互相递归。
                        guardThis->refreshLoadedModuleEvidenceAsync();
                    }
                    else if (guardThis->m_moduleEvidenceStatusLabel != nullptr)
                    {
                        guardThis->m_moduleEvidenceStatusLabel->setText(
                            driverText(
                                "driver.evidence.status.no_modules_short",
                                QStringLiteral("证据：没有可聚合的模块。")));
                    }

                    info << refreshEvent
                        << driverText(
                            "driver.log.refresh_modules_completed",
                            QStringLiteral("[DriverDock] 刷新模块完成, count="))
                        << guardThis->m_loadedModuleCache.size() << eol;
                },
                Qt::QueuedConnection);
        });
    collectModuleTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(collectModuleTask);
}

void DriverDock::fillObjectDriverNameFromSelection()
{
    // 从当前服务行推导 DriverObject 名称：
    // - 大多数服务名与 \Driver\Name 一致；
    // - 如果用户已手工输入内容，本按钮仍明确覆盖，避免隐式猜测。
    if (m_serviceTable == nullptr ||
        m_serviceTable->selectionModel() == nullptr ||
        m_objectDriverNameEdit == nullptr)
    {
        return;
    }

    const QModelIndexList rowList = m_serviceTable->selectionModel()->selectedRows(0);
    if (rowList.isEmpty())
    {
        m_objectInfoStatusLabel->setText(
            driverText("driver.object.status.select_service", QStringLiteral("状态：请先在驱动服务表选中一行。")));
        return;
    }

    QTableWidgetItem* serviceNameItem = m_serviceTable->item(rowList.front().row(), 0);
    if (serviceNameItem == nullptr)
    {
        return;
    }

    const QString serviceNameText = serviceNameItem->data(Qt::UserRole).toString().trimmed();
    if (serviceNameText.isEmpty())
    {
        return;
    }
    m_objectDriverNameEdit->setText(QStringLiteral("\\Driver\\%1").arg(serviceNameText));
    if (m_tabWidget != nullptr && m_objectInfoPage != nullptr)
    {
        m_tabWidget->setCurrentWidget(m_objectInfoPage);
    }
}

void DriverDock::showServiceTableContextMenu(const QPoint& localPosition)
{
    // 右键菜单入口：
    // - 普通 SCM 操作仍使用既有按钮/函数；
    // - 三种卸载互相独立：SCM 标准卸载、直接调用 DriverUnload、DriverObject 强拆。
    if (m_serviceTable == nullptr)
    {
        return;
    }

    const QModelIndex clickedIndex = m_serviceTable->indexAt(localPosition);
    if (clickedIndex.isValid())
    {
        m_serviceTable->selectRow(clickedIndex.row());
        syncOperateFormBySelectedService();
    }

    const QModelIndexList selectedRows =
        (m_serviceTable->selectionModel() == nullptr)
        ? QModelIndexList()
        : m_serviceTable->selectionModel()->selectedRows(0);
    if (selectedRows.isEmpty())
    {
        return;
    }

    // QMenu::exec 会进入嵌套事件循环；清理操作必须在进入前复制不可变目标，
    // 不能在用户确认后重新按可能已刷新的 rowIndex 读取服务名或路径。
    const int selectedServiceRowIndex = selectedRows.front().row();
    const QTableWidgetItem* selectedServiceNameItem =
        m_serviceTable->item(selectedServiceRowIndex, 0);
    const QTableWidgetItem* selectedServicePathItem =
        m_serviceTable->item(selectedServiceRowIndex, 5);
    const QString selectedCleanupServiceName =
        selectedServiceNameItem != nullptr
        ? selectedServiceNameItem->data(Qt::UserRole).toString().trimmed()
        : QString();
    const QString selectedSearchServiceName =
        !selectedCleanupServiceName.isEmpty()
        ? selectedCleanupServiceName
        : (selectedServiceNameItem != nullptr
            ? selectedServiceNameItem->text().trimmed()
            : QString());
    const QString selectedCleanupServicePath =
        selectedServicePathItem != nullptr
        ? driverScCleanupNormalizePath(selectedServicePathItem->text())
        : QString();

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* fillObjectNameAction = contextMenu.addAction(
        QIcon(":/Icon/process_details.svg"),
        driverText("driver.menu.fill_driver_object", QStringLiteral("填充 DriverObject 名称")));
    QAction* queryObjectAction = contextMenu.addAction(
        QIcon(":/Icon/process_refresh.svg"),
        driverText("driver.menu.query_driver_object", QStringLiteral("查询 DriverObject 信息")));
    QAction* copyRowAction = contextMenu.addAction(
        QIcon(":/Icon/process_copy_row.svg"),
        driverText("driver.menu.copy_row", QStringLiteral("复制当前行")));
    QAction* searchDriverOnlineAction = contextMenu.addAction(
        QIcon(":/Icon/file_find.svg"),
        driverText(
            "driver.menu.search_bing",
            QStringLiteral("使用 Bing 搜索驱动信息")));
    searchDriverOnlineAction->setToolTip(driverText(
        "driver.menu.search_bing.tooltip",
        QStringLiteral("仅在默认浏览器中打开与所选驱动有关的 Bing 搜索，不读取或处理搜索结果。")));
    contextMenu.addSeparator();
    QAction* stopServiceAction = contextMenu.addAction(
        QIcon(":/Icon/process_terminate.svg"),
        driverText("driver.menu.stop_service", QStringLiteral("标准卸载（SCM / sc stop）")));
    stopServiceAction->setToolTip(
        driverText(
            "driver.menu.stop_service.tooltip",
            QStringLiteral("通过服务控制管理器发送 SERVICE_CONTROL_STOP，走 Windows 标准驱动卸载路径。")));
    QAction* scCleanupAction = contextMenu.addAction(
        QIcon(":/Icon/process_terminate.svg"),
        driverText(
            "driver.menu.sc_unload_cleanup",
            QStringLiteral("sc卸载并清理文件注册表")));
    scCleanupAction->setToolTip(driverText(
        "driver.menu.sc_unload_cleanup.tooltip",
        QStringLiteral("严格等待 SCM 到达 SERVICE_STOPPED；停前停后均复核服务路径与独占引用，随后删除服务注册和驱动文件。")));
    const bool serviceCleanupTargetReady =
        !selectedCleanupServiceName.isEmpty() &&
        !selectedCleanupServicePath.isEmpty();
    scCleanupAction->setEnabled(
        serviceCleanupTargetReady && !m_scCleanupRunning);
    if (m_scCleanupRunning)
    {
        scCleanupAction->setToolTip(driverText(
            "driver.menu.sc_unload_cleanup.running",
            QStringLiteral("已有 sc 卸载清理任务正在后台运行，请等待完成。")));
    }
    else if (!serviceCleanupTargetReady)
    {
        scCleanupAction->setToolTip(driverText(
            "driver.menu.sc_unload_cleanup.invalid_service_target",
            QStringLiteral("当前服务缺少可安全解析的绝对 .sys 路径，无法执行清理。")));
    }
    QAction* forceUnloadAction = contextMenu.addAction(
        QIcon(":/Icon/process_terminate.svg"),
        driverText("driver.menu.force_unload_driver_object", QStringLiteral("直接调用 DriverUnload")));
    forceUnloadAction->setToolTip(
        driverText(
            "driver.menu.force_unload_driver_object.tooltip",
            QStringLiteral("跳过 SCM/ZwUnloadDriver，仅调用 DriverObject->DriverUnload；不修改 MajorFunction，不强停线程，不强删设备。")));
    QAction* forceDestructiveUnloadAction = contextMenu.addAction(
        QIcon(":/Icon/process_terminate.svg"),
        driverText("driver.menu.destructive_unload_driver_object", QStringLiteral("DriverObject 强拆")));
    forceDestructiveUnloadAction->setToolTip(
        driverText(
            "driver.menu.destructive_unload_driver_object.tooltip",
            QStringLiteral("固定顺序：封 MajorFunction → 终止目标驱动线程 → 调 DriverUnload → 解除并删除设备链至 DeviceObject 为空。")));

    QAction* selectedAction = contextMenu.exec(m_serviceTable->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == fillObjectNameAction)
    {
        fillObjectDriverNameFromSelection();
        return;
    }
    if (selectedAction == queryObjectAction)
    {
        fillObjectDriverNameFromSelection();
        querySelectedDriverObjectInfo();
        return;
    }
    if (selectedAction == copyRowAction)
    {
        copyDriverOperationCurrentRow(m_serviceTable);
        return;
    }
    if (selectedAction == searchDriverOnlineAction)
    {
        if (!openDriverBingSearch(
            selectedSearchServiceName,
            selectedCleanupServicePath))
        {
            QMessageBox::warning(
                this,
                driverText(
                    "driver.search_bing.failed.title",
                    QStringLiteral("无法打开浏览器")),
                driverText(
                    "driver.search_bing.failed.body",
                    QStringLiteral("系统未能打开 Bing 搜索页面，请检查默认浏览器设置。")));
        }
        return;
    }
    if (selectedAction == stopServiceAction)
    {
        stopDriverServiceFromServiceRow(selectedRows.front().row());
        return;
    }
    if (selectedAction == scCleanupAction)
    {
        scUnloadAndCleanupDriver(
            selectedCleanupServiceName,
            selectedCleanupServicePath);
        return;
    }
    if (selectedAction == forceUnloadAction)
    {
        forceUnloadDriverFromServiceRow(selectedRows.front().row(), false);
        return;
    }
    if (selectedAction == forceDestructiveUnloadAction)
    {
        const QMessageBox::StandardButton confirmResult = QMessageBox::warning(
            this,
            driverText("driver.confirm.destructive_unload.title", QStringLiteral("DriverObject 强拆")),
            driverText(
                "driver.confirm.destructive_unload.body",
                QStringLiteral("该操作会绕过 SCM/PnP 生命周期，并严格按以下顺序执行：\n\n1. 将 MajorFunction/FastIo 改为拒绝入口\n2. 强制终止并等待该驱动镜像内的所有系统线程退出\n3. 调用 DriverObject->DriverUnload（若存在）\n4. 解除上下层设备关联并删除全部 DeviceObject，直至 DriverObject->DeviceObject 为空\n\n任一线程无法确认退出时不会继续调用 DriverUnload。该操作可能立即导致蓝屏，仅用于恶意驱动处置。\n\n是否继续？")),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (confirmResult == QMessageBox::Yes)
        {
            forceUnloadDriverFromServiceRow(selectedRows.front().row(), true);
        }
        return;
    }
}

void DriverDock::stopDriverServiceFromServiceRow(const int rowIndex)
{
    // 服务列表停驱流程：
    // - 输入：服务表格行号。
    // - 处理：读取 SCM 服务短名，在后台线程调用 ControlService(SERVICE_CONTROL_STOP)；
    // - 返回：无返回值；结果通过操作日志和刷新后的服务/模块表体现。
    // 注意：这里刻意不调用 R0 DriverObject 强卸载。直接调用第三方 DriverUnload
    // 或清理 DriverObject/DeviceObject 会绕过 SCM/PnP 生命周期，目标仍在处理 IRP
    // 时容易导致 bugcheck。
    if (m_serviceTable == nullptr || rowIndex < 0 || rowIndex >= m_serviceTable->rowCount())
    {
        return;
    }

    QTableWidgetItem* serviceNameItem = m_serviceTable->item(rowIndex, 0);
    if (serviceNameItem == nullptr)
    {
        return;
    }

    const QString serviceNameText = serviceNameItem->data(Qt::UserRole).toString().trimmed();
    if (serviceNameText.isEmpty())
    {
        appendOperateLogLine(
            driverText("driver.operation.stop.empty_name", QStringLiteral("停止服务失败：服务名为空。")));
        return;
    }

    appendOperateLogLine(
        driverText("driver.operation.stop.starting", QStringLiteral("开始停止驱动服务（SCM）：%1"))
        .arg(serviceNameText));

    QPointer<DriverDock> guardThis(this);
    const std::wstring serviceNameWide = toWideString(serviceNameText);
    auto* stopTask = QRunnable::create([guardThis, serviceNameText, serviceNameWide]()
        {
            ks::service::ServiceStatus finalStatus{};
            std::string errorText;
            std::uint32_t errorCode = 0U;
            const bool stopOk = ks::service::StopServiceByName(
                serviceNameWide,
                10000U,
                SERVICE_STOPPED,
                &finalStatus,
                &errorText,
                &errorCode);

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, serviceNameText, stopOk, finalStatus, errorText, errorCode]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }

                    if (stopOk)
                    {
                        guardThis->appendOperateLogLine(
                            finalStatus.currentState == SERVICE_STOPPED
                            ? driverText("driver.operation.stop.success", QStringLiteral("停止服务成功：service=%1"))
                                .arg(serviceNameText)
                            : driverText(
                                "driver.operation.stop.completed",
                                QStringLiteral("停止服务结束：service=%1，当前状态=%2"))
                            .arg(serviceNameText)
                            .arg(guardThis->serviceStateToText(finalStatus.currentState)));
                    }
                    else
                    {
                        (void)ks::ui::promptForPrivilegeFailure(
                            guardThis,
                            QStringLiteral("停止驱动服务"),
                            errorCode);
                        guardThis->appendOperateLogLine(
                            driverText(
                                "driver.operation.stop.failed",
                                QStringLiteral("停止服务失败：service=%1，error=%2，detail=%3"))
                            .arg(serviceNameText)
                            .arg(errorCode)
                            .arg(QString::fromUtf8(errorText.c_str())));
                    }
                    guardThis->refreshDriverServiceRecords();
                    guardThis->refreshLoadedKernelModuleRecords();
                },
                Qt::QueuedConnection);
        });
    stopTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(stopTask);
}

void DriverDock::scUnloadAndCleanupDriver(
    const QString& serviceName,
    const QString& normalizedBinaryPath)
{
    if (m_scCleanupRunning)
    {
        appendOperateLogLine(driverText(
            "driver.cleanup.already_running",
            QStringLiteral("已有 sc 卸载清理任务正在运行，本次请求未执行。")));
        return;
    }

    const QString serviceNameText = serviceName.trimmed();
    const QString confirmedPath =
        driverScCleanupNormalizePath(normalizedBinaryPath);
    if (serviceNameText.isEmpty() ||
        confirmedPath.isEmpty() ||
        confirmedPath.compare(
            normalizedBinaryPath,
            Qt::CaseInsensitive) != 0)
    {
        QMessageBox::warning(
            this,
            driverText(
                "driver.cleanup.title",
                QStringLiteral("sc 卸载并清理")),
            driverText(
                "driver.cleanup.invalid_target",
                QStringLiteral("目标服务名或驱动路径无效。仅允许清理可解析为绝对 .sys 文件的 SCM 驱动服务。")));
        return;
    }

    const QString featureName = driverText(
        "driver.cleanup.feature_name",
        QStringLiteral("sc 卸载并清理驱动文件和服务注册"));
    if (!ks::ui::requestAdministratorRestartForFeature(this, featureName))
    {
        return;
    }

    const QMessageBox::StandardButton confirmation =
        QMessageBox::warning(
            this,
            driverText(
                "driver.cleanup.title",
                QStringLiteral("sc 卸载并清理")),
            driverText(
                "driver.cleanup.confirm_body",
                QStringLiteral(
                    "目标服务：%1\n"
                    "驱动文件：%2\n\n"
                    "该操作不可逆，将严格按以下顺序执行：\n"
                    "1. 复核当前 SCM 配置路径，确认没有其它驱动服务共享该文件；\n"
                    "2. 通过 SCM 发送 SERVICE_CONTROL_STOP，并等待 SERVICE_STOPPED；\n"
                    "3. 停止后再次复核配置路径和非共享状态；\n"
                    "4. 删除服务注册；仅删除成功后才删除驱动文件。\n\n"
                    "如果停止失败或未到 SERVICE_STOPPED，服务注册和文件都不会被删除。"
                    "如果服务注册已删除但文件删除失败，将保留孤立文件且不会自动恢复服务注册，"
                    "需要手动处理该部分成功状态。\n\n是否继续？"))
                .arg(serviceNameText, confirmedPath),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
    if (confirmation != QMessageBox::Yes)
    {
        return;
    }

    // 强确认改为直接点击：不再要求输入确认短语，默认聚焦“否”避免误触。
    const auto strongConfirmation = QMessageBox::warning(
        this,
        driverText(
            "driver.cleanup.strong_confirm_title",
            QStringLiteral("不可逆清理强确认")),
        driverText(
            "driver.cleanup.strong_confirm_final",
            QStringLiteral("确认执行卸载并清理？服务注册与驱动文件将被删除，且无法撤销。")),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (strongConfirmation != QMessageBox::Yes)
    {
        return;
    }

    appendOperateLogLine(
        driverText(
            "driver.cleanup.started",
            QStringLiteral("开始 sc 卸载并清理：service=%1，path=%2"))
        .arg(serviceNameText, confirmedPath));
    m_scCleanupRunning = true;

    QPointer<DriverDock> guardThis(this);
    auto* cleanupTask = QRunnable::create(
        [guardThis, serviceNameText, confirmedPath]()
        {
            const DriverScCleanupResult cleanupResult =
                driverScUnloadAndCleanup(serviceNameText, confirmedPath);

            // 结果先投递到长生命周期 GUI receiver；到 GUI 线程后再检查 QPointer，
            // 避免 worker 线程把可能已析构的 DriverDock raw pointer 当 receiver。
            QCoreApplication* application = QCoreApplication::instance();
            if (application == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                application,
                [guardThis, serviceNameText, cleanupResult]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }

                    guardThis->m_scCleanupRunning = false;
                    const QString stageText =
                        driverScCleanupStageText(cleanupResult.stage);
                    if (cleanupResult.ok)
                    {
                        const QString fileStateText = cleanupResult.fileWasMissing
                            ? driverText(
                                "driver.cleanup.file_already_missing",
                                QStringLiteral("文件原本已不存在（视为已清理）"))
                            : driverText(
                                "driver.cleanup.file_deleted",
                                QStringLiteral("文件已删除"));
                        const QString successText = driverText(
                            "driver.cleanup.success",
                            QStringLiteral(
                                "sc 卸载清理完成。\n\n"
                                "服务：%1\n"
                                "服务注册：已删除或已标记删除\n"
                                "驱动文件：%2\n"
                                "文件状态：%3"))
                            .arg(
                                serviceNameText,
                                cleanupResult.normalizedPath,
                                fileStateText);
                        guardThis->appendOperateLogLine(
                            driverText(
                                "driver.cleanup.success_log",
                                QStringLiteral("sc 卸载清理完成：service=%1，path=%2，file=%3"))
                            .arg(
                                serviceNameText,
                                cleanupResult.normalizedPath,
                                fileStateText));
                        QMessageBox::information(
                            guardThis,
                            driverText(
                                "driver.cleanup.title",
                                QStringLiteral("sc 卸载并清理")),
                            successText);
                    }
                    else
                    {
                        (void)ks::ui::promptForPrivilegeFailure(
                            guardThis,
                            driverText(
                                "driver.cleanup.feature_name",
                                QStringLiteral("sc 卸载并清理驱动文件和服务注册")),
                            cleanupResult.win32Error);

                        QString detailText;
                        if (!cleanupResult.sharedServiceNames.isEmpty())
                        {
                            detailText = driverText(
                                "driver.cleanup.shared_services_detail",
                                QStringLiteral("同一驱动文件仍被这些服务引用：%1"))
                                .arg(cleanupResult.sharedServiceNames.join(
                                    QStringLiteral(", ")));
                        }
                        else
                        {
                            detailText = driverText(
                                "driver.cleanup.failure_detail",
                                QStringLiteral("该阶段的实时安全校验或系统调用未通过；后续删除已按安全策略中止。"));
                            if (cleanupResult.win32Error != ERROR_SUCCESS)
                            {
                                detailText = driverText(
                                    "driver.cleanup.failure_detail_with_system",
                                    QStringLiteral("%1\n系统消息：%2"))
                                    .arg(
                                        detailText,
                                        DriverDock::formatWin32ErrorText(
                                            cleanupResult.win32Error));
                            }
                        }
                        QString failureText;
                        if (cleanupResult.serviceDeleted)
                        {
                            failureText = driverText(
                                "driver.cleanup.partial_failure",
                                QStringLiteral(
                                    "sc 卸载清理部分成功：服务已停止且服务注册已删除或已标记删除，"
                                    "但驱动文件删除失败。不会自动恢复已删除的服务注册。\n\n"
                                    "服务：%1\n驱动文件：%2\n"
                                    "失败阶段：%3\nWin32：%4\n详情：%5"))
                                .arg(serviceNameText)
                                .arg(cleanupResult.normalizedPath)
                                .arg(stageText)
                                .arg(cleanupResult.win32Error)
                                .arg(detailText);
                        }
                        else if (cleanupResult.stopReached)
                        {
                            failureText = driverText(
                                "driver.cleanup.post_stop_failure",
                                QStringLiteral(
                                    "sc 卸载清理已中止：服务已到达 SERVICE_STOPPED，"
                                    "但后续复核或服务注册删除失败。"
                                    "服务注册和驱动文件均未删除。\n\n"
                                    "服务：%1\n驱动文件：%2\n"
                                    "失败阶段：%3\nWin32：%4\n详情：%5"))
                                .arg(serviceNameText)
                                .arg(cleanupResult.normalizedPath)
                                .arg(stageText)
                                .arg(cleanupResult.win32Error)
                                .arg(detailText);
                        }
                        else
                        {
                            failureText = driverText(
                                "driver.cleanup.pre_stop_failure",
                                QStringLiteral(
                                    "sc 卸载清理未执行破坏性清理：停止前复核失败，"
                                    "或未确认服务到达 SERVICE_STOPPED。"
                                    "服务注册和驱动文件均未删除；服务可能仍在停止过程中。\n\n"
                                    "服务：%1\n驱动文件：%2\n"
                                    "失败阶段：%3\nWin32：%4\n详情：%5"))
                                .arg(serviceNameText)
                                .arg(cleanupResult.normalizedPath)
                                .arg(stageText)
                                .arg(cleanupResult.win32Error)
                                .arg(detailText);
                        }
                        guardThis->appendOperateLogLine(
                            driverText(
                                "driver.cleanup.failure_log",
                                QStringLiteral("sc 卸载清理失败：service=%1，stage=%2，error=%3，detail=%4"))
                            .arg(serviceNameText)
                            .arg(stageText)
                            .arg(cleanupResult.win32Error)
                            .arg(detailText));
                        QMessageBox::warning(
                            guardThis,
                            driverText(
                                "driver.cleanup.title",
                                QStringLiteral("sc 卸载并清理")),
                            failureText);
                    }

                    guardThis->refreshDriverServiceRecords();
                    guardThis->refreshLoadedKernelModuleRecords();
                },
                Qt::QueuedConnection);
        });
    cleanupTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(cleanupTask);
}

void DriverDock::forceUnloadDriverFromServiceRow(const int rowIndex, const bool destructiveCleanup)
{
    // 强制卸载流程：
    // - 使用服务名推导 \Driver\ServiceName；
    // - R0 内部再通过 ObReferenceObjectByName 引用对象；
    // - destructiveCleanup=false：跳过系统路径，只调用 DriverUnload；
    // - destructiveCleanup=true：执行固定顺序的 DriverObject 强拆。
    if (m_serviceTable == nullptr || rowIndex < 0 || rowIndex >= m_serviceTable->rowCount())
    {
        return;
    }

    QTableWidgetItem* serviceNameItem = m_serviceTable->item(rowIndex, 0);
    if (serviceNameItem == nullptr)
    {
        return;
    }

    const QString serviceNameText = serviceNameItem->data(Qt::UserRole).toString().trimmed();
    if (serviceNameText.isEmpty())
    {
        appendOperateLogLine(
            driverText("driver.operation.force_unload.empty_name", QStringLiteral("强制卸载失败：服务名为空。")));
        return;
    }

    const QString driverObjectNameText = QStringLiteral("\\Driver\\%1").arg(serviceNameText);
    appendOperateLogLine(
        driverText("driver.operation.force_unload.starting", QStringLiteral("开始 R0 强制卸载：%1"))
        .arg(driverObjectNameText));

    QPointer<DriverDock> guardThis(this);
    const std::wstring driverObjectNameWide = driverObjectNameText.toStdWString();
    auto* unloadTask = QRunnable::create([guardThis, driverObjectNameText, driverObjectNameWide, destructiveCleanup]()
        {
            unsigned long cleanupFlags = KSWORD_ARK_DRIVER_UNLOAD_FLAG_DIRECT_UNLOAD_CALL;
            if (destructiveCleanup)
            {
                cleanupFlags = KSWORD_ARK_DRIVER_UNLOAD_FLAG_ALLOW_DESTRUCTIVE_CLEANUP |
                    KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN;
            }
            const ksword::ark::DriverForceUnloadResult result =
                ksword::ark::DriverClient().forceUnloadDriver(
                    driverObjectNameWide,
                    cleanupFlags,
                    3000UL);

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, driverObjectNameText, destructiveCleanup, result]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }

                    const QString resultLine = driverText(
                        "driver.operation.force_unload.result",
                        QStringLiteral(
                            "驱动卸载完成：%1 | IO说明=%2 | Status=%3 | Flags=%4 | Applied=%5 | Deleted=%6 | Detached=%7 | Threads=%8/%9 fail=%10 last=%11 | Last=%12 | Wait=%13 | Object=%14 | Unload=%15 | Name=%16"))
                        .arg(driverObjectNameText)
                        .arg(friendlyDriverIoMessage(result.io.message))
                        .arg(driverForceUnloadStatusText(result.status))
                        .arg(formatHex32(result.flags))
                        .arg(formatHex32(result.cleanupFlagsApplied))
                        .arg(result.deletedDeviceCount)
                        .arg(result.detachedDeviceCount)
                        .arg(result.threadsTerminated)
                        .arg(result.threadCandidates)
                        .arg(result.threadFailures)
                        .arg(formatNtStatusText(result.threadLastStatus))
                        .arg(formatNtStatusText(result.lastStatus))
                        .arg(formatNtStatusText(result.waitStatus))
                        .arg(formatCompactAddress(result.driverObjectAddress))
                        .arg(formatCompactAddress(result.driverUnloadAddress))
                        .arg(QString::fromStdWString(result.driverName));
                    guardThis->appendOperateLogLine(resultLine);
                    if (destructiveCleanup)
                    {
                        guardThis->appendOperateLogLine(
                            driverText(
                                "driver.operation.high_risk_notice",
                                QStringLiteral("已执行 DriverObject 强拆请求：封 MajorFunction → 停目标线程 → 调 DriverUnload → 拆空 DeviceObject 链。")));
                    }
                    guardThis->refreshDriverServiceRecords();
                    guardThis->refreshLoadedKernelModuleRecords();
                },
                Qt::QueuedConnection);
        });
    unloadTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(unloadTask);
}

void DriverDock::showModuleTableContextMenu(const QPoint& localPosition)
{
    // 模块表右键入口：
    // - 服务已停止但模块仍残留时，服务名路径可能已经失效；
    // - 这里改用模块基址，让 R0 扫描对象目录反查 DriverObject。
    if (m_moduleTable == nullptr)
    {
        return;
    }

    const QModelIndex clickedIndex = m_moduleTable->indexAt(localPosition);
    if (clickedIndex.isValid())
    {
        m_moduleTable->selectRow(clickedIndex.row());
    }

    const QModelIndexList selectedRows =
        (m_moduleTable->selectionModel() == nullptr)
        ? QModelIndexList()
        : m_moduleTable->selectionModel()->selectedRows(0);
    if (selectedRows.isEmpty())
    {
        return;
    }

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* refreshEvidenceAction = contextMenu.addAction(
        QIcon(":/Icon/process_refresh.svg"),
        driverText("driver.menu.refresh_module_evidence", QStringLiteral("刷新模块证据聚合")));
    QAction* copyEvidenceAction = contextMenu.addAction(
        QIcon(":/Icon/process_copy_row.svg"),
        driverText("driver.menu.copy_module_evidence", QStringLiteral("复制当前模块证据详情")));
    QAction* copyRowAction = contextMenu.addAction(
        QIcon(":/Icon/process_copy_row.svg"),
        driverText("driver.menu.copy_row", QStringLiteral("复制当前行")));
    QAction* searchDriverOnlineAction = contextMenu.addAction(
        QIcon(":/Icon/file_find.svg"),
        driverText(
            "driver.menu.search_bing",
            QStringLiteral("使用 Bing 搜索驱动信息")));
    searchDriverOnlineAction->setToolTip(driverText(
        "driver.menu.search_bing.tooltip",
        QStringLiteral("仅在默认浏览器中打开与所选驱动有关的 Bing 搜索，不读取或处理搜索结果。")));
    QAction* dumpModuleMemoryAction = contextMenu.addAction(
        QIcon(":/Icon/disk_save.svg"),
        driverText("driver.menu.dump_module_memory", QStringLiteral("R0 Dump 模块内存…")));
    dumpModuleMemoryAction->setToolTip(driverText(
        "driver.menu.dump_module_memory.tooltip",
        QStringLiteral("按已加载模块基址读取完整内存映像；不可读或已释放页面按 00 保留地址布局，并在协议、PE 与身份复核通过后原子保存。")));
    QAction* queryKernelSignatureAction = contextMenu.addAction(
        driverText("driver.menu.query_kernel_signature", QStringLiteral("R0 读取内核签名证据")));
    QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
        &contextMenu,
        this,
        [this]() -> ks::online_scan::SandboxUploadTarget
        {
            // 输入：DriverDock 已加载模块表当前行。
            // 处理：读取路径列并规范化 \SystemRoot/\Device 等内核路径。
            // 返回：待上传驱动文件路径和来源说明。
            ks::online_scan::SandboxUploadTarget uploadTarget;
            const int rowIndex = m_moduleTable != nullptr ? m_moduleTable->currentRow() : -1;
            const QTableWidgetItem* pathItem =
                (m_moduleTable != nullptr && rowIndex >= 0)
                ? m_moduleTable->item(rowIndex, ModuleImagePathColumn)
                : nullptr;
            const QTableWidgetItem* nameItem =
                (m_moduleTable != nullptr && rowIndex >= 0) ? m_moduleTable->item(rowIndex, 0) : nullptr;
            if (pathItem == nullptr)
            {
                uploadTarget.errorText = driverText(
                    "driver.upload.module_path_missing",
                    QStringLiteral("当前模块行没有可用路径。"));
                return uploadTarget;
            }
            uploadTarget.filePath = ks::online_scan::normalizeKernelImagePathForUpload(pathItem->text());
            uploadTarget.sourceText = driverText("driver.upload.module_source", QStringLiteral("驱动模块 %1"))
                .arg(nameItem != nullptr ? nameItem->text() : QStringLiteral("<未知模块>"));
            return uploadTarget;
        });
    if (uploadVirusTotalAction != nullptr)
    {
        uploadVirusTotalAction->setEnabled(!selectedRows.isEmpty());
    }
    contextMenu.addSeparator();
    QAction* scCleanupAction = contextMenu.addAction(
        QIcon(":/Icon/process_terminate.svg"),
        driverText(
            "driver.menu.sc_unload_cleanup",
            QStringLiteral("sc卸载并清理文件注册表")));
    scCleanupAction->setToolTip(driverText(
        "driver.menu.sc_unload_cleanup.module_tooltip",
        QStringLiteral("仅当模块完整路径在当前 SCM 驱动服务缓存中唯一匹配时，才允许走标准 sc 停止并清理。")));
    QAction* forceCleanupByBaseAction = contextMenu.addAction(
        QIcon(":/Icon/process_terminate.svg"),
        driverText("driver.menu.force_unload_by_base", QStringLiteral("按模块基址直接调用 DriverUnload")));
    forceCleanupByBaseAction->setToolTip(
        driverText(
            "driver.menu.force_unload_by_base.tooltip",
            QStringLiteral("按模块基址反查 DriverObject，跳过系统卸载路径，仅调用 DriverUnload。")));
    QAction* forceDeepCleanupByBaseAction = contextMenu.addAction(
        QIcon(":/Icon/process_terminate.svg"),
        driverText("driver.menu.deep_cleanup_by_base", QStringLiteral("按模块基址 DriverObject 强拆")));
    forceDeepCleanupByBaseAction->setToolTip(
        driverText(
            "driver.menu.deep_cleanup_by_base.tooltip",
            QStringLiteral("先封 MajorFunction、终止并确认目标线程退出，再清理可验证回调、调用 DriverUnload，并解除/删除设备链。")));
    contextMenu.addSeparator();
    QAction* blindCommunicationAction = contextMenu.addAction(
        QIcon(":/Icon/process_critical.svg"),
        driverText("driver.menu.blind_irp", QStringLiteral("致盲 IRP 通信…")));
    blindCommunicationAction->setToolTip(
        driverText(
            "driver.menu.blind_irp.tooltip",
            QStringLiteral("按模块基址精确定位 DriverObject，只拒绝 CREATE/READ/WRITE/DEVICE_CONTROL/INTERNAL_DEVICE_CONTROL；保留 Cleanup、Close、PnP、Power 和 FastIo。")));
    QAction* restoreCommunicationAction = contextMenu.addAction(
        QIcon(":/Icon/process_resume.svg"),
        driverText("driver.menu.restore_irp", QStringLiteral("恢复 IRP 通信")));
    restoreCommunicationAction->setToolTip(
        driverText(
            "driver.menu.restore_irp.tooltip",
            QStringLiteral("只恢复仍由本功能接管的 MajorFunction；检测到第三方改写时不会覆盖对方入口。")));

    // 致盲是危险写操作：只有证据缓存证明 canonical DriverObject 与模块基址一致时启用。
    // 恢复按 R0 保存的模块基址记录查找，因此即使证据刷新失败也必须保留逃生入口。
    const int selectedRowIndex = selectedRows.front().row();
    QString selectedModuleName;
    QString selectedModulePath;
    std::uint64_t selectedModuleBase = 0U;
    std::size_t sourceIndex = m_loadedModuleEvidenceCache.size();
    {
        // QMenu::exec 会运行嵌套事件循环；所有表项指针仅在进入该循环前使用。
        const QTableWidgetItem* selectedModuleNameItem =
            m_moduleTable->item(selectedRowIndex, 0);
        const QTableWidgetItem* selectedModuleBaseItem =
            m_moduleTable->item(selectedRowIndex, 1);
        const QTableWidgetItem* selectedModulePathItem =
            m_moduleTable->item(selectedRowIndex, ModuleImagePathColumn);
        selectedModuleName =
            selectedModuleNameItem != nullptr
            ? selectedModuleNameItem->text().trimmed()
            : QString();
        selectedModulePath =
            selectedModulePathItem != nullptr
            ? selectedModulePathItem->text().trimmed()
            : QString();
        selectedModuleBase =
            selectedModuleBaseItem != nullptr
            ? selectedModuleBaseItem->data(Qt::UserRole).toULongLong()
            : 0U;
        sourceIndex =
            selectedModuleNameItem != nullptr
            ? static_cast<std::size_t>(
                selectedModuleNameItem->data(ModuleRecordIndexRole).toULongLong())
            : m_loadedModuleEvidenceCache.size();
    }

    // 仅按规范化完整路径做唯一匹配；不使用模块名/文件名猜测 SCM 服务，
    // 防止同名驱动位于不同目录时停止并删除错误目标。
    const QString normalizedModulePath =
        driverScCleanupNormalizePath(selectedModulePath);
    QString selectedCleanupServiceName;
    QString selectedCleanupServicePath;
    std::size_t cleanupServiceMatchCount = 0U;
    if (!normalizedModulePath.isEmpty())
    {
        for (const DriverServiceRecord& serviceRecord : m_driverServiceCache)
        {
            const QString candidatePath =
                driverScCleanupNormalizePath(serviceRecord.binaryPath);
            if (!candidatePath.isEmpty() &&
                candidatePath.compare(
                    normalizedModulePath,
                    Qt::CaseInsensitive) == 0)
            {
                ++cleanupServiceMatchCount;
                selectedCleanupServiceName = serviceRecord.serviceName.trimmed();
                selectedCleanupServicePath = candidatePath;
            }
        }
    }
    const bool moduleCleanupTargetReady =
        cleanupServiceMatchCount == 1U &&
        !selectedCleanupServiceName.isEmpty() &&
        !selectedCleanupServicePath.isEmpty();
    scCleanupAction->setEnabled(
        moduleCleanupTargetReady && !m_scCleanupRunning);
    if (m_scCleanupRunning)
    {
        scCleanupAction->setToolTip(driverText(
            "driver.menu.sc_unload_cleanup.running",
            QStringLiteral("已有 sc 卸载清理任务正在后台运行，请等待完成。")));
    }
    else if (!moduleCleanupTargetReady)
    {
        scCleanupAction->setToolTip(driverText(
            "driver.menu.sc_unload_cleanup.module_unresolved",
            QStringLiteral("当前模块完整路径无法在驱动服务缓存中唯一匹配 SCM 服务；请刷新服务和模块后重试。")));
    }

    QString selectedDriverObjectName;
    std::uint64_t selectedDriverObjectAddress = 0U;
    bool selectedDriverObjectResolved = false;
    bool selectedDriverStartMatchesBase = false;
    if (sourceIndex < m_loadedModuleEvidenceCache.size())
    {
        const LoadedModuleEvidenceRecord& evidence =
            m_loadedModuleEvidenceCache[sourceIndex];
        selectedDriverObjectName = evidence.driverObjectName.trimmed();
        selectedDriverObjectAddress = evidence.driverObjectAddress;
        selectedDriverObjectResolved = evidence.driverObjectResolved;
        selectedDriverStartMatchesBase = evidence.driverStartMatchesBase;
    }
    const bool exactTargetReady =
        selectedDriverObjectResolved &&
        selectedDriverStartMatchesBase &&
        !selectedDriverObjectName.isEmpty() &&
        selectedDriverObjectAddress != 0U;
    dumpModuleMemoryAction->setEnabled(
        selectedModuleBase != 0U && !m_moduleDumpRunning);
    if (m_moduleDumpRunning)
    {
        dumpModuleMemoryAction->setToolTip(driverText(
            "driver.menu.dump_module_memory.running",
            QStringLiteral("已有模块内存 Dump 正在后台运行，请等待完成。")));
    }
    blindCommunicationAction->setEnabled(selectedModuleBase != 0U && exactTargetReady);
    restoreCommunicationAction->setEnabled(selectedModuleBase != 0U);
    if (!exactTargetReady)
    {
        blindCommunicationAction->setToolTip(
            driverText(
                "driver.menu.blind_irp.requires_evidence",
                QStringLiteral("请先刷新模块证据；仅当 canonical DriverObject、对象地址已解析且 DriverStart 与模块基址一致时允许致盲。")));
    }

    QAction* selectedAction = contextMenu.exec(m_moduleTable->viewport()->mapToGlobal(localPosition));
    if (selectedAction == refreshEvidenceAction)
    {
        refreshLoadedModuleEvidenceAsync();
        return;
    }
    if (selectedAction == copyEvidenceAction)
    {
        showSelectedModuleEvidenceDetail();
        if (m_moduleEvidenceDetailEditor != nullptr && QGuiApplication::clipboard() != nullptr)
        {
            QGuiApplication::clipboard()->setText(m_moduleEvidenceDetailEditor->text());
        }
        return;
    }
    if (selectedAction == copyRowAction)
    {
        copyDriverOperationCurrentRow(m_moduleTable);
        return;
    }
    if (selectedAction == searchDriverOnlineAction)
    {
        if (!openDriverBingSearch(selectedModuleName, selectedModulePath))
        {
            QMessageBox::warning(
                this,
                driverText(
                    "driver.search_bing.failed.title",
                    QStringLiteral("无法打开浏览器")),
                driverText(
                    "driver.search_bing.failed.body",
                    QStringLiteral("系统未能打开 Bing 搜索页面，请检查默认浏览器设置。")));
        }
        return;
    }
    if (selectedAction == dumpModuleMemoryAction)
    {
        dumpSelectedModuleMemory(
            selectedModuleName,
            selectedModulePath,
            selectedModuleBase);
        return;
    }
    if (selectedAction == queryKernelSignatureAction)
    {
        querySelectedModuleKernelSignature();
        return;
    }
    if (selectedAction == uploadVirusTotalAction)
    {
        return;
    }
    if (selectedAction == scCleanupAction)
    {
        scUnloadAndCleanupDriver(
            selectedCleanupServiceName,
            selectedCleanupServicePath);
        return;
    }
    if (selectedAction == blindCommunicationAction)
    {
        const QMessageBox::StandardButton confirmResult = QMessageBox::warning(
            this,
            driverText(
                "driver.confirm.blind_irp.title",
                QStringLiteral("致盲 IRP 通信")),
            driverText(
                "driver.confirm.blind_irp.body",
                QStringLiteral(
                    "目标模块：%1\nDriverObject：%2\n对象地址：%3\n模块基址：%4\n\n"
                    "将把以下 5 个通信入口替换为系统拒绝入口：\n"
                    "CREATE / READ / WRITE / DEVICE_CONTROL / INTERNAL_DEVICE_CONTROL\n\n"
                    "不会卸载驱动，也不会停止线程、回调、DPC、共享内存通信或已在途 IRP；"
                    "Cleanup、Close、PnP、Power、SystemControl、Shutdown 和 FastIo 保持不变。"
                    "该操作仍可能导致应用访问失败、设备异常、系统卡死或蓝屏。\n\n"
                    "未被第三方改写且仍由本功能持有的入口可通过“恢复 IRP 通信”撤销；"
                    "冲突槽只报告、不覆盖。是否继续？"))
                .arg(selectedModuleName)
                .arg(selectedDriverObjectName)
                .arg(formatCompactAddress(selectedDriverObjectAddress))
                .arg(formatCompactAddress(selectedModuleBase)),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (confirmResult == QMessageBox::Yes)
        {
            controlDriverCommunication(
                selectedModuleBase,
                selectedModuleName,
                selectedDriverObjectName,
                selectedDriverObjectAddress,
                false);
        }
        return;
    }
    if (selectedAction == restoreCommunicationAction)
    {
        controlDriverCommunication(
            selectedModuleBase,
            selectedModuleName,
            selectedDriverObjectName,
            selectedDriverObjectAddress,
            true);
        return;
    }
    if (selectedAction == forceCleanupByBaseAction)
    {
        // 普通模块基址清理不需要二次确认，直接复用当前选中行。
        forceUnloadDriverFromModuleRow(selectedRows.front().row(), false, false);
        return;
    }
    if (selectedAction == forceDeepCleanupByBaseAction)
    {
        // 强力清理是高风险动作，因此保留二次确认：
        // - 全局 QMessageBox 主题器已不再拦截 Close 事件；
        // - 这里可以恢复使用标准按钮返回值，避免业务层绕过全局弹窗语义。
        const QMessageBox::StandardButton confirmResult = QMessageBox::warning(
            this,
            driverText("driver.confirm.deep_cleanup.title", QStringLiteral("R0 强力清理")),
            driverText(
                "driver.confirm.deep_cleanup.body",
                QStringLiteral("该操作会按模块基址反查 DriverObject，并执行完整强拆：封 MajorFunction、终止并等待目标驱动线程、清理可验证回调、调用 DriverUnload、解除并删除全部设备对象。\n\n不会摘 PsLoadedModuleList，但可能立即导致系统崩溃。\n\n是否继续？")),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (confirmResult == QMessageBox::Yes)
        {
            forceUnloadDriverFromModuleRow(selectedRows.front().row(), true, true);
        }
        return;
    }
}

void DriverDock::dumpSelectedModuleMemory(
    const QString& moduleNameSnapshot,
    const QString& rawPathSnapshot,
    const std::uint64_t moduleBase)
{
    if (m_moduleDumpRunning)
    {
        return;
    }
    const QString moduleName = moduleNameSnapshot.trimmed();
    const QString rawPath = rawPathSnapshot.trimmed();
    const QString ntPath = buildKernelSignatureNtPath(rawPath);
    if (moduleBase == 0U ||
        rawPath.isEmpty() ||
        rawPath == QStringLiteral("<unknown>") ||
        ntPath.isEmpty())
    {
        QMessageBox::warning(
            this,
            driverText(
                "driver.dump_module.title",
                QStringLiteral("R0 Dump 模块内存")),
            driverText(
                "driver.dump_module.invalid_selection",
                QStringLiteral("当前模块缺少有效的加载基址或映像路径，无法执行 R0 Dump。")));
        return;
    }

    QString safeModuleName = moduleName;
    safeModuleName.replace(
        QRegularExpression(QStringLiteral(R"([<>:"/\\|?*\x00-\x1F])")),
        QStringLiteral("_"));
    if (safeModuleName.isEmpty())
    {
        safeModuleName = QStringLiteral("kernel-module");
    }
    const QString targetPath = QFileDialog::getSaveFileName(
        this,
        driverText(
            "driver.dump_module.browse_title",
            QStringLiteral("选择模块内存 Dump 保存路径")),
        QDir::home().filePath(safeModuleName + QStringLiteral(".memory.bin")),
        driverText(
            "driver.dump_module.file_filter",
            QStringLiteral("模块内存镜像 (*.bin *.dmp);;所有文件 (*.*)")));
    if (targetPath.trimmed().isEmpty())
    {
        return;
    }

    const QString normalizedTargetPath =
        QFileInfo(targetPath).absoluteFilePath();
    if (driverOperationHasUnsafeWin32PathSyntax(
        normalizedTargetPath,
        true))
    {
        QMessageBox::warning(
            this,
            driverText(
                "driver.dump_module.title",
                QStringLiteral("R0 Dump 模块内存")),
            driverText(
                "driver.dump_module.unsafe_path",
                QStringLiteral("保存路径包含设备命名空间、备用数据流或其它不安全的 Win32 路径语法。请选择普通的本地或 UNC 文件路径。")));
        return;
    }
    const QString sourceWin32Path =
        ks::online_scan::normalizeKernelImagePathForUpload(rawPath);
    const QString sourcePathKey =
        driverModuleDumpPathIdentityKey(sourceWin32Path);
    const QString targetPathKey =
        driverModuleDumpPathIdentityKey(normalizedTargetPath);
    const bool sameSourcePath =
        !sourcePathKey.isEmpty() &&
        sourcePathKey == targetPathKey;
    if (sameSourcePath || QFileInfo::exists(normalizedTargetPath))
    {
        // 所有已存在目标（包括原始 .sys 及其硬链接）均拒绝，因此不存在覆盖窗口。
        QMessageBox::warning(
            this,
            driverText(
                "driver.dump_module.title",
                QStringLiteral("R0 Dump 模块内存")),
            driverText(
                "driver.dump_module.no_overwrite",
                QStringLiteral("目标文件已经存在。为保护原始驱动及已有证据，本功能绝不覆盖文件；请选择新的文件名。")));
        return;
    }

    m_moduleDumpRunning = true;
    if (m_overviewStatusLabel != nullptr)
    {
        m_overviewStatusLabel->setText(driverText(
            "driver.dump_module.status.running",
            QStringLiteral("状态：正在后台 R0 Dump 模块 %1…"))
            .arg(moduleName));
    }
    appendOperateLogLine(driverText(
        "driver.dump_module.log.started",
        QStringLiteral("开始 R0 Dump 模块内存：%1，基址=%2，目标=%3"))
        .arg(moduleName)
        .arg(formatCompactAddress(moduleBase))
        .arg(normalizedTargetPath));

    QPointer<DriverDock> guardThis(this);
    auto* dumpTask = QRunnable::create(
        [guardThis, moduleName, ntPath, moduleBase, normalizedTargetPath]()
        {
            const DriverModuleDumpResult dumpResult =
                driverModuleDumpToFile(ntPath, moduleBase, normalizedTargetPath);
            QCoreApplication* application = QCoreApplication::instance();
            if (application == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                application,
                [guardThis, moduleName, dumpResult]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    guardThis->m_moduleDumpRunning = false;
                    if (dumpResult.ok)
                    {
                        if (guardThis->m_overviewStatusLabel != nullptr)
                        {
                            guardThis->m_overviewStatusLabel->setText(driverText(
                                "driver.dump_module.status.complete",
                                QStringLiteral("状态：模块 %1 的 R0 Dump 已完成（%2 字节）"))
                                .arg(moduleName)
                                .arg(dumpResult.moduleSize));
                        }
                        guardThis->appendOperateLogLine(driverText(
                            "driver.dump_module.log.complete",
                            QStringLiteral("R0 Dump 模块内存完成：%1，%2 字节，补零分块=%3，保存到 %4"))
                            .arg(moduleName)
                            .arg(dumpResult.moduleSize)
                            .arg(dumpResult.zeroFilledChunkCount)
                            .arg(dumpResult.targetPath));
                        QString completionText = driverText(
                            "driver.dump_module.complete",
                            QStringLiteral(
                                "模块内存 Dump 完成。\n\n"
                                "模块：%1\n"
                                "基址：%2\n"
                                "映像大小：%3 字节\n"
                                "保存路径：%4\n\n"
                                "R0 已在读取前后复核同一已加载模块的基址、名称和大小；"
                                "内存 PE 的 SizeOfImage 也与 R0 模块边界一致。"))
                            .arg(moduleName)
                            .arg(formatCompactAddress(dumpResult.moduleBase))
                            .arg(dumpResult.moduleSize)
                            .arg(dumpResult.targetPath);
                        if (dumpResult.zeroFilledChunkCount > 0U)
                        {
                            completionText += QString::fromLatin1("\n\n") + driverText(
                                "driver.dump_module.zero_fill_notice",
                                QStringLiteral(
                                    "其中 %1 个读取分块包含不可读或已释放页面；R0 已用 00 保留这些页面的地址布局。"))
                                .arg(dumpResult.zeroFilledChunkCount);
                        }
                        QMessageBox::information(
                            guardThis,
                            driverText(
                                "driver.dump_module.title",
                                QStringLiteral("R0 Dump 模块内存")),
                            completionText);
                        return;
                    }

                    QString failureDetail =
                        driverModuleDumpErrorText(dumpResult.error);
                    if (dumpResult.win32Error != ERROR_SUCCESS)
                    {
                        failureDetail = driverText(
                            "driver.dump_module.error.with_win32",
                            QStringLiteral("%1\nWin32：%2"))
                            .arg(
                                failureDetail,
                                DriverDock::formatWin32ErrorText(
                                    dumpResult.win32Error));
                    }
                    if (!dumpResult.technicalDetail.trimmed().isEmpty())
                    {
                        failureDetail += QString::fromLatin1("\n\n") +
                            dumpResult.technicalDetail.trimmed();
                    }
                    if (guardThis->m_overviewStatusLabel != nullptr)
                    {
                        guardThis->m_overviewStatusLabel->setText(driverText(
                            "driver.dump_module.status.failed",
                            QStringLiteral("状态：模块 %1 的 R0 Dump 失败，未生成目标文件。"))
                            .arg(moduleName));
                    }
                    guardThis->appendOperateLogLine(driverText(
                        "driver.dump_module.log.failed",
                        QStringLiteral("R0 Dump 模块内存失败：%1；%2"))
                        .arg(moduleName)
                        .arg(failureDetail));
                    QMessageBox::critical(
                        guardThis,
                        driverText(
                            "driver.dump_module.title",
                            QStringLiteral("R0 Dump 模块内存")),
                        driverText(
                            "driver.dump_module.failed",
                            QStringLiteral(
                                "模块内存 Dump 失败，原子临时文件已取消，目标文件未创建。\n\n"
                                "模块：%1\n详情：%2"))
                            .arg(moduleName)
                            .arg(failureDetail));
                },
                Qt::QueuedConnection);
        });
    dumpTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(dumpTask);
}

void DriverDock::querySelectedModuleKernelSignature()
{
    if (m_moduleTable == nullptr)
    {
        return;
    }
    const int rowIndex = m_moduleTable->currentRow();
    const QTableWidgetItem* nameItem = rowIndex >= 0 ? m_moduleTable->item(rowIndex, 0) : nullptr;
    const QTableWidgetItem* baseItem = rowIndex >= 0 ? m_moduleTable->item(rowIndex, 1) : nullptr;
    const QTableWidgetItem* pathItem = rowIndex >= 0
        ? m_moduleTable->item(rowIndex, ModuleImagePathColumn)
        : nullptr;
    const QString moduleName = nameItem != nullptr ? nameItem->text().trimmed() : QString();
    const QString rawPath = pathItem != nullptr ? pathItem->text().trimmed() : QString();
    const QString ntPath = buildKernelSignatureNtPath(rawPath);
    const std::uint64_t moduleBase = baseItem != nullptr
        ? baseItem->data(Qt::UserRole).toULongLong()
        : 0U;
    if (rowIndex < 0 || ntPath.isEmpty() || moduleBase == 0U)
    {
        if (m_moduleEvidenceStatusLabel != nullptr)
        {
            m_moduleEvidenceStatusLabel->setText(driverText(
                "driver.signature.status.invalid_selection",
                QStringLiteral("内核签名查询失败：当前模块缺少有效路径或基址。")));
        }
        return;
    }

    if (m_moduleEvidenceStatusLabel != nullptr)
    {
        m_moduleEvidenceStatusLabel->setText(driverText(
            "driver.signature.status.querying",
            QStringLiteral("正在通过 R0 读取模块签名证据：%1"))
            .arg(moduleName));
    }
    if (m_moduleEvidenceDetailEditor != nullptr)
    {
        m_moduleEvidenceDetailEditor->setLocalizedText(
            QStringLiteral("R0 签名证据查询中..."));
    }

    QPointer<DriverDock> guardThis(this);
    auto* queryTask = QRunnable::create([guardThis, moduleName, rawPath, ntPath, moduleBase]()
        {
            const ksword::ark::ImageSignatureQueryResult signatureResult =
                ksword::ark::DriverClient().queryImageSignature(ntPath.toStdWString(), moduleBase);
            DriverDock* targetDock = guardThis.data();
            if (targetDock == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(
                targetDock,
                [guardThis, moduleName, rawPath, ntPath, moduleBase, signatureResult]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    QString report;
                    report += QStringLiteral("[R0 内核签名证据]\n");
                    report += QStringLiteral("模块: %1\n").arg(moduleName);
                    report += QStringLiteral("原始路径: %1\n").arg(rawPath);
                    report += QStringLiteral("NT 路径: %1\n").arg(ntPath);
                    report += QStringLiteral("模块基址: %1\n\n").arg(formatCompactAddress(moduleBase));
                    report += QString::fromStdString(ksword::ark::formatImageSignatureEvidence(signatureResult));
                    report += QStringLiteral("\n");
                    report += QStringLiteral("结论边界：PE 证书表结构不等于证书链可信；CI cached signing level 是独立的内核缓存结果。此查询未调用 WinTrust。已加载模块绑定仅核对枚举基址和文件名；证书表仍来自当前磁盘文件。");
                    if (guardThis->m_moduleEvidenceDetailEditor != nullptr)
                    {
                        guardThis->m_moduleEvidenceDetailEditor->setLocalizedText(report);
                    }
                    if (guardThis->m_moduleEvidenceStatusLabel != nullptr)
                    {
                        guardThis->m_moduleEvidenceStatusLabel->setText(signatureResult.io.ok
                            ? driverText(
                                "driver.signature.status.complete",
                                QStringLiteral("R0 内核签名证据读取完成：%1"))
                                .arg(moduleName)
                            : driverText(
                                "driver.signature.status.failed",
                                QStringLiteral("R0 内核签名证据读取失败：%1（Win32=%2）"))
                                .arg(moduleName)
                                .arg(signatureResult.io.win32Error));
                    }
                },
                Qt::QueuedConnection);
        });
    queryTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(queryTask);
}

void DriverDock::forceUnloadDriverFromModuleRow(
    const int rowIndex,
    const bool removeCallbacksFirst,
    const bool destructiveCleanup)
{
    // 按模块基址清理：
    // - R3 只传模块基址和模块名兜底文本；
    // - R0 先按 DriverStart 反查真实 DriverObject，再执行分级强制卸载；
    // - removeCallbacksFirst 为 true 时请求 R0 在 DriverObject 处理成功后移除可验证回调；
    // - destructiveCleanup=false：按模块基址反查后只调用 DriverUnload；
    // - destructiveCleanup=true：执行封 dispatch、停线程、调 unload、拆设备的固定强拆顺序。
    if (m_moduleTable == nullptr || rowIndex < 0 || rowIndex >= m_moduleTable->rowCount())
    {
        return;
    }

    QTableWidgetItem* moduleNameItem = m_moduleTable->item(rowIndex, 0);
    QTableWidgetItem* moduleBaseItem = m_moduleTable->item(rowIndex, 1);
    if (moduleNameItem == nullptr || moduleBaseItem == nullptr)
    {
        return;
    }

    const QString moduleNameText = moduleNameItem->text().trimmed();
    const std::uint64_t moduleBaseValue = moduleBaseItem->data(Qt::UserRole).toULongLong();
    if (moduleBaseValue == 0U)
    {
        appendOperateLogLine(
            driverText("driver.operation.module_cleanup.empty_base", QStringLiteral("模块基址清理失败：模块基址为空。")));
        return;
    }

    QString fallbackNameText = moduleNameText;
    if (fallbackNameText.endsWith(QStringLiteral(".sys"), Qt::CaseInsensitive))
    {
        fallbackNameText.chop(4);
    }

    appendOperateLogLine(
        driverText("driver.operation.module_cleanup.starting", QStringLiteral("开始 R0 按模块基址%1：%2 | base=%3"))
        .arg(removeCallbacksFirst
            ? driverText(
                "driver.operation.module_cleanup.mode.callbacks",
                QStringLiteral("强力清理回调+DriverObject"))
            : driverText(
                "driver.operation.module_cleanup.mode.force_unload",
                QStringLiteral("强制卸载 DriverObject")))
        .arg(moduleNameText, formatCompactAddress(moduleBaseValue)));

    QPointer<DriverDock> guardThis(this);
    const std::wstring fallbackNameWide = fallbackNameText.toStdWString();
    auto* unloadTask = QRunnable::create([guardThis, moduleNameText, moduleBaseValue, fallbackNameWide, removeCallbacksFirst, destructiveCleanup]()
        {
            unsigned long cleanupFlags =
                KSWORD_ARK_DRIVER_UNLOAD_FLAG_TARGET_MODULE_BASE_PRESENT |
                KSWORD_ARK_DRIVER_UNLOAD_FLAG_DIRECT_UNLOAD_CALL;
            if (destructiveCleanup)
            {
                cleanupFlags |= KSWORD_ARK_DRIVER_UNLOAD_FLAG_ALLOW_DESTRUCTIVE_CLEANUP |
                    KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN;
            }
            if (removeCallbacksFirst)
            {
                cleanupFlags |= KSWORD_ARK_DRIVER_UNLOAD_FLAG_REMOVE_CALLBACKS_BY_MODULE_BASE;
            }
            const ksword::ark::DriverForceUnloadResult result =
                ksword::ark::DriverClient().forceUnloadDriverByModuleBase(
                    moduleBaseValue,
                    fallbackNameWide,
                    cleanupFlags,
                    3000UL);

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, moduleNameText, moduleBaseValue, removeCallbacksFirst, destructiveCleanup, result]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }

                    const QString resultLine = driverText(
                        "driver.operation.module_cleanup.result",
                        QStringLiteral(
                            "R0 模块基址%1完成：%2 | Base=%3 | IO说明=%4 | Status=%5 | Flags=%6 | Applied=%7 | Deleted=%8 | Detached=%9 | Threads=%10/%11 fail=%12 last=%13 | Last=%14 | Wait=%15 | Object=%16 | Unload=%17 | Callbacks=%18/%19 fail=%20 last=%21 | Name=%22"))
                        .arg(removeCallbacksFirst
                            ? driverText("driver.operation.module_cleanup.mode.deep", QStringLiteral("强力清理"))
                            : driverText("driver.operation.module_cleanup.mode.clean", QStringLiteral("清理")))
                        .arg(moduleNameText)
                        .arg(formatCompactAddress(moduleBaseValue))
                        .arg(friendlyDriverIoMessage(result.io.message))
                        .arg(driverForceUnloadStatusText(result.status))
                        .arg(formatHex32(result.flags))
                        .arg(formatHex32(result.cleanupFlagsApplied))
                        .arg(result.deletedDeviceCount)
                        .arg(result.detachedDeviceCount)
                        .arg(result.threadsTerminated)
                        .arg(result.threadCandidates)
                        .arg(result.threadFailures)
                        .arg(formatNtStatusText(result.threadLastStatus))
                        .arg(formatNtStatusText(result.lastStatus))
                        .arg(formatNtStatusText(result.waitStatus))
                        .arg(formatCompactAddress(result.driverObjectAddress))
                        .arg(formatCompactAddress(result.driverUnloadAddress))
                        .arg(result.callbacksRemoved)
                        .arg(result.callbackCandidates)
                        .arg(result.callbackFailures)
                        .arg(formatNtStatusText(result.callbackLastStatus))
                        .arg(QString::fromStdWString(result.driverName));
                    guardThis->appendOperateLogLine(resultLine);
                    if (destructiveCleanup)
                    {
                        guardThis->appendOperateLogLine(
                            driverText(
                                "driver.operation.high_risk_notice",
                                QStringLiteral("已执行 DriverObject 强拆请求：封 MajorFunction → 停目标线程 → 调 DriverUnload → 拆空 DeviceObject 链。")));
                    }
                    guardThis->refreshDriverServiceRecords();
                    guardThis->refreshLoadedKernelModuleRecords();
                },
                Qt::QueuedConnection);
        });
    unloadTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(unloadTask);
}

void DriverDock::querySelectedDriverObjectInfo()
{
    // DriverObject 查询：
    // - 只接受对象名，不接受地址；
    // - 后台线程中通过 ArkDriverClient 访问 KswordARK，避免阻塞 UI。
    if (m_objectInfoQuerying || m_objectDriverNameEdit == nullptr)
    {
        return;
    }

    const QString driverNameText = m_objectDriverNameEdit->text().trimmed();
    if (driverNameText.isEmpty())
    {
        if (m_objectInfoStatusLabel != nullptr)
        {
            m_objectInfoStatusLabel->setText(
                driverText("driver.object.status.name_empty", QStringLiteral("状态：DriverObject 名称不能为空。")));
        }
        return;
    }

    m_objectInfoQuerying = true;
    const std::uint64_t ticketValue = ++m_objectInfoQueryTicket;
    if (m_queryObjectInfoButton != nullptr)
    {
        m_queryObjectInfoButton->setEnabled(false);
    }
    if (m_objectInfoStatusLabel != nullptr)
    {
        m_objectInfoStatusLabel->setText(
            driverText("driver.object.status.querying", QStringLiteral("状态：正在查询 DriverObject...")));
    }

    QPointer<DriverDock> guardThis(this);
    const std::wstring driverNameWide = driverNameText.toStdWString();
    auto* queryTask = QRunnable::create([guardThis, ticketValue, driverNameWide]()
        {
            const ksword::ark::DriverObjectQueryResult result =
                ksword::ark::DriverClient().queryDriverObject(
                    driverNameWide,
                    KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_ALL,
                    KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT,
                    KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT);

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, ticketValue, result]()
                {
                    if (guardThis == nullptr ||
                        guardThis->m_objectInfoQueryTicket != ticketValue)
                    {
                        return;
                    }
                    guardThis->applyDriverObjectQueryResult(result);
                },
                Qt::QueuedConnection);
        });
    queryTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(queryTask);
}

void DriverDock::applyDriverObjectQueryResult(const ksword::ark::DriverObjectQueryResult& result)
{
    // DriverObject 查询会一次重建对象、派遣、设备、扩展、Fast I/O 五张证据表。
    const QPointer<DriverDock> guardThis(this);
    const auto deferredResult =
        std::make_shared<ksword::ark::DriverObjectQueryResult>(result);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("driver-object-evidence-apply"),
        {
            m_driverObjectEvidenceTable,
            m_majorFunctionTable,
            m_deviceObjectTable,
            m_driverExtensionEvidenceTable,
            m_fastIoEvidenceTable
        },
        [guardThis, deferredResult]()
        {
            if (!guardThis.isNull())
            {
                guardThis->applyDriverObjectQueryResult(*deferredResult);
            }
        }))
    {
        return;
    }

    // 查询结果回填：
    // - 所有地址都作为诊断文本展示；
    // - 不在 UI 中将地址作为任何二次操作输入。
    m_objectInfoQuerying = false;
    m_lastDriverObjectQueryResult = result;
    m_hasDriverObjectQueryResult = true;
    if (m_queryObjectInfoButton != nullptr)
    {
        m_queryObjectInfoButton->setEnabled(true);
    }

    if (m_objectInfoStatusLabel != nullptr)
    {
        const QString readableIoText = friendlyDriverIoMessage(result.io.message);
        m_objectInfoStatusLabel->setText(
            driverText("driver.object.status.io", QStringLiteral("状态：%1 | %2"))
            .arg(result.io.ok ? driverObjectQueryStatusText(result.queryStatus) : QStringLiteral("IO failed"))
            .arg(readableIoText));
    }

    if (m_objectInfoSummaryEdit != nullptr)
    {
        const QString readableIoText = friendlyDriverIoMessage(result.io.message);
        QStringList summaryLines;
        summaryLines << QStringLiteral("[DriverObject]");
        summaryLines << driverText("driver.object.summary.io_note", QStringLiteral("IO说明: %1"))
            .arg(readableIoText);
        summaryLines << QStringLiteral("QueryStatus: %1").arg(driverObjectQueryStatusText(result.queryStatus));
        summaryLines << QStringLiteral("LastStatus: %1").arg(formatNtStatusText(result.lastStatus));
        summaryLines << QStringLiteral("DriverName: %1").arg(QString::fromStdWString(result.driverName));
        summaryLines << QStringLiteral("ServiceKey: %1").arg(QString::fromStdWString(result.serviceKeyName));
        summaryLines << QStringLiteral("ImagePath: %1").arg(QString::fromStdWString(result.imagePath));
        summaryLines << QStringLiteral("DriverObject: %1").arg(formatCompactAddress(result.driverObjectAddress));
        summaryLines << QStringLiteral("DriverStart: %1 Size=%2")
            .arg(formatCompactAddress(result.driverStart))
            .arg(formatHex32(result.driverSize));
        summaryLines << QStringLiteral("DriverSection: %1").arg(formatCompactAddress(result.driverSection));
        summaryLines << QStringLiteral("DriverUnload: %1").arg(formatCompactAddress(result.driverUnload));
        summaryLines << QStringLiteral("Flags: %1 FieldFlags=%2")
            .arg(formatHex32(result.driverFlags))
            .arg(formatHex32(result.fieldFlags));
        summaryLines << QStringLiteral("MajorFunctions: %1 DeviceObjects: %2/%3")
            .arg(result.majorFunctions.size())
            .arg(result.devices.size())
            .arg(result.totalDeviceCount);
        m_objectInfoSummaryEdit->setText(summaryLines.join('\n'));
    }
    rebuildDriverObjectEvidenceViews();
}

void DriverDock::rebuildDriverObjectEvidenceViews()
{
    // 输入：当前 DriverObject 缓存与完整性缓存。
    // 处理：仅在 UI 线程投影为只读表格，不重新访问驱动。
    // 返回：无。
    if (!m_hasDriverObjectQueryResult)
    {
        if (m_driverObjectPageSummaryEdit != nullptr)
        {
            m_driverObjectPageSummaryEdit->setText(
                driverText("driver.object.page_summary.query_first", QStringLiteral("请先执行 DriverObject 查询。")));
        }
        if (m_driverExtensionStatusLabel != nullptr)
        {
            m_driverExtensionStatusLabel->setText(
                driverText(
                    "driver.object.driver_extension.status.waiting",
                    QStringLiteral("状态：等待 DriverObject 查询。")));
        }
        if (m_fastIoStatusLabel != nullptr)
        {
            m_fastIoStatusLabel->setText(
                driverText(
                    "driver.object.fast_io.status.waiting",
                    QStringLiteral("状态：等待 Driver Integrity 证据。")));
        }
        return;
    }

    const ksword::ark::DriverObjectQueryResult& result = m_lastDriverObjectQueryResult;
    if (m_driverObjectPageSummaryEdit != nullptr)
    {
        QStringList lines;
        lines << QStringLiteral("DriverObject: %1").arg(formatCompactAddress(result.driverObjectAddress));
        lines << QStringLiteral("DriverStart: %1").arg(formatCompactAddress(result.driverStart));
        lines << QStringLiteral("DriverSection: %1").arg(formatCompactAddress(result.driverSection));
        lines << QStringLiteral("DriverUnload: %1").arg(formatCompactAddress(result.driverUnload));
        lines << QStringLiteral("DriverSize: %1").arg(formatHex32(result.driverSize));
        lines << QStringLiteral("DriverFlags: %1").arg(formatHex32(result.driverFlags));
        lines << QStringLiteral("MajorFunctions: %1").arg(result.majorFunctions.size());
        lines << QStringLiteral("DeviceObjects: %1/%2").arg(result.devices.size()).arg(result.totalDeviceCount);
        m_driverObjectPageSummaryEdit->setText(lines.join('\n'));
    }

    if (m_driverObjectEvidenceTable != nullptr)
    {
        const QSignalBlocker blocker(m_driverObjectEvidenceTable);
        m_driverObjectEvidenceTable->setSortingEnabled(false);
        m_driverObjectEvidenceTable->setRowCount(0);
        const QStringList rows = {
            QStringLiteral("DriverObject"),
            QStringLiteral("DriverStart"),
            QStringLiteral("DriverSection"),
            QStringLiteral("DriverUnload"),
            QStringLiteral("DriverSize"),
            QStringLiteral("DriverFlags"),
            QStringLiteral("FieldFlags"),
            QStringLiteral("MajorFunctionCount"),
            QStringLiteral("DeviceCount")
        };
        const QStringList values = {
            formatCompactAddress(result.driverObjectAddress),
            formatCompactAddress(result.driverStart),
            formatCompactAddress(result.driverSection),
            formatCompactAddress(result.driverUnload),
            formatHex32(result.driverSize),
            formatHex32(result.driverFlags),
            formatHex32(result.fieldFlags),
            QString::number(result.majorFunctions.size()),
            QStringLiteral("%1/%2").arg(result.devices.size()).arg(result.totalDeviceCount)
        };
        m_driverObjectEvidenceTable->setRowCount(rows.size());
        for (int index = 0; index < rows.size(); ++index)
        {
            appendEvidenceRow(
                m_driverObjectEvidenceTable,
                index,
                rows[index],
                values[index],
                QStringLiteral("-"),
                driverText("driver.integrity.risk.normal", QStringLiteral("正常")),
                QStringLiteral("100"),
                driverText("driver.object.evidence.read_only_summary", QStringLiteral("DriverObject 只读摘要")));
        }
        m_driverObjectEvidenceTable->setSortingEnabled(true);
    }

    if (m_majorFunctionTable != nullptr)
    {
        const QSignalBlocker blocker(m_majorFunctionTable);
        m_majorFunctionTable->setSortingEnabled(false);
        m_majorFunctionTable->setRowCount(0);
        for (const ksword::ark::DriverMajorFunctionEntry& majorEntry : result.majorFunctions)
        {
            const int rowIndex = m_majorFunctionTable->rowCount();
            m_majorFunctionTable->insertRow(rowIndex);
            m_majorFunctionTable->setItem(rowIndex, 0, createReadOnlyItem(driverMajorFunctionName(majorEntry.majorFunction)));
            m_majorFunctionTable->setItem(rowIndex, 1, createReadOnlyItem(formatCompactAddress(majorEntry.dispatchAddress)));
            m_majorFunctionTable->setItem(rowIndex, 2, createReadOnlyItem(QString::fromStdWString(majorEntry.moduleName).isEmpty()
                ? QStringLiteral("-")
                : QString::fromStdWString(majorEntry.moduleName)));
            m_majorFunctionTable->setItem(rowIndex, 3, createReadOnlyItem(formatCompactAddress(majorEntry.moduleBase)));
            m_majorFunctionTable->setItem(rowIndex, 4, createReadOnlyItem(driverDispatchLocationText(majorEntry.flags)));
            if ((majorEntry.flags & 0x00000002U) == 0U)
            {
                for (int columnIndex = 0; columnIndex < m_majorFunctionTable->columnCount(); ++columnIndex)
                {
                    QTableWidgetItem* cellItem = m_majorFunctionTable->item(rowIndex, columnIndex);
                    if (cellItem != nullptr)
                    {
                        cellItem->setToolTip(
                            driverText(
                                "driver.object.major_function.external_tooltip",
                                QStringLiteral("Dispatch 不在 DriverObject 自身镜像范围内。")));
                    }
                }
            }
        }
        m_majorFunctionTable->setSortingEnabled(true);
    }

    if (m_deviceObjectTable != nullptr)
    {
        const QSignalBlocker blocker(m_deviceObjectTable);
        m_deviceObjectTable->setSortingEnabled(false);
        m_deviceObjectTable->setRowCount(0);
        for (const ksword::ark::DriverDeviceEntry& deviceEntry : result.devices)
        {
            const int rowIndex = m_deviceObjectTable->rowCount();
            m_deviceObjectTable->insertRow(rowIndex);
            m_deviceObjectTable->setItem(rowIndex, 0, createReadOnlyItem(deviceEntry.relationDepth == 0U
                ? QStringLiteral("Root")
                : QStringLiteral("Attached +%1").arg(deviceEntry.relationDepth)));
            m_deviceObjectTable->setItem(rowIndex, 1, createReadOnlyItem(formatCompactAddress(deviceEntry.deviceObjectAddress)));
            QTableWidgetItem* nameItem = createReadOnlyItem(QString::fromStdWString(deviceEntry.deviceName).isEmpty()
                ? QStringLiteral("(unnamed)")
                : QString::fromStdWString(deviceEntry.deviceName));
            nameItem->setToolTip(QStringLiteral("NameStatus=%1").arg(formatNtStatusText(deviceEntry.nameStatus)));
            m_deviceObjectTable->setItem(rowIndex, 2, nameItem);
            m_deviceObjectTable->setItem(rowIndex, 3, createReadOnlyItem(driverDeviceTypeText(deviceEntry.deviceType)));
            m_deviceObjectTable->setItem(rowIndex, 4, createReadOnlyItem(formatHex32(deviceEntry.flags)));
            m_deviceObjectTable->setItem(rowIndex, 5, createReadOnlyItem(formatHex32(deviceEntry.characteristics)));
            m_deviceObjectTable->setItem(rowIndex, 6, createReadOnlyItem(QString::number(deviceEntry.stackSize)));
            m_deviceObjectTable->setItem(rowIndex, 7, createReadOnlyItem(formatCompactAddress(deviceEntry.nextDeviceObjectAddress)));
            m_deviceObjectTable->setItem(rowIndex, 8, createReadOnlyItem(formatCompactAddress(deviceEntry.attachedDeviceObjectAddress)));
            m_deviceObjectTable->setItem(rowIndex, 9, createReadOnlyItem(formatCompactAddress(deviceEntry.driverObjectAddress)));
        }
        m_deviceObjectTable->setSortingEnabled(true);
    }

    if (m_driverExtensionStatusLabel != nullptr)
    {
        m_driverExtensionStatusLabel->setText(
            driverText(
                "driver.object.driver_extension.status.projected",
                QStringLiteral("状态：DriverExtension 未直接暴露；当前仅展示 DriverObject / DeviceChain / FastIo 关联证据。")));
    }
    if (m_driverExtensionEvidenceTable != nullptr)
    {
        const QSignalBlocker blocker(m_driverExtensionEvidenceTable);
        m_driverExtensionEvidenceTable->setSortingEnabled(false);
        m_driverExtensionEvidenceTable->setRowCount(0);
        const QStringList evidenceNames = {
            QStringLiteral("DriverExtension"),
            QStringLiteral("DeviceChain"),
            QStringLiteral("MajorFunction"),
            QStringLiteral("FastIo")
        };
        const QStringList detailTexts = {
            driverText(
                "driver.object.driver_extension.detail.unavailable",
                QStringLiteral("当前 R3 协议未直接返回 DriverExtension 指针。")),
            driverText(
                "driver.object.driver_extension.detail.device_chain",
                QStringLiteral("DeviceObject 链已由对象页展示。")),
            driverText(
                "driver.object.driver_extension.detail.major_function",
                QStringLiteral("MajorFunction 表已由对象页展示。")),
            driverText(
                "driver.object.driver_extension.detail.fast_io",
                QStringLiteral("FastIo 仅在完整性页中作为证据归档。"))
        };
        m_driverExtensionEvidenceTable->setRowCount(evidenceNames.size());
        for (int index = 0; index < evidenceNames.size(); ++index)
        {
            appendEvidenceRow(
                m_driverExtensionEvidenceTable,
                index,
                evidenceNames[index],
                QStringLiteral("Unavailable"),
                QStringLiteral("-"),
                driverText("driver.evidence.status.unknown", QStringLiteral("未知")),
                QStringLiteral("0"),
                detailTexts[index]);
        }
        m_driverExtensionEvidenceTable->setSortingEnabled(true);
    }

    if (m_fastIoStatusLabel != nullptr)
    {
        m_fastIoStatusLabel->setText(
            driverText(
                "driver.object.fast_io.status.projected",
                QStringLiteral("状态：FastIo 关联证据由 Driver Integrity 页回填，当前记录数 %1。"))
            .arg(m_driverIntegrityCache.size()));
    }
    if (m_fastIoEvidenceTable != nullptr)
    {
        const QSignalBlocker blocker(m_fastIoEvidenceTable);
        m_fastIoEvidenceTable->setSortingEnabled(false);
        m_fastIoEvidenceTable->setRowCount(0);
        int visibleRows = 0;
        for (const auto& row : m_driverIntegrityCache)
        {
            if (row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_FAST_IO &&
                row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT &&
                row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MAJOR_FUNCTION &&
                row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION)
            {
                continue;
            }
            const int rowIndex = m_fastIoEvidenceTable->rowCount();
            m_fastIoEvidenceTable->insertRow(rowIndex);
            appendEvidenceRow(
                m_fastIoEvidenceTable,
                rowIndex,
                integrityClassText(row.evidenceClass),
                formatCompactAddress(row.objectAddress),
                formatCompactAddress(row.targetAddress),
                integrityRiskText(row.riskFlags),
                QString::number(row.confidence),
                QString::fromStdWString(row.detail));
            ++visibleRows;
        }
        if (visibleRows == 0)
        {
            m_fastIoEvidenceTable->setRowCount(1);
            appendEvidenceRow(
                m_fastIoEvidenceTable,
                0,
                QStringLiteral("FastIo"),
                QStringLiteral("Unavailable"),
                QStringLiteral("-"),
                driverText("driver.integrity.risk.normal", QStringLiteral("正常")),
                QStringLiteral("0"),
                driverText(
                    "driver.object.fast_io.empty",
                    QStringLiteral("当前 Driver Integrity 缓存未返回 FastIo 证据。")));
        }
        m_fastIoEvidenceTable->setSortingEnabled(true);
    }
}

void DriverDock::rebuildDriverServiceTableByFilter()
{
    if (m_serviceTable == nullptr)
    {
        return;
    }

    const QString filterText = m_serviceFilterEdit != nullptr
        ? m_serviceFilterEdit->text().trimmed()
        : QString();

    m_serviceTable->setRowCount(0);
    int visibleCount = 0;
    for (const DriverServiceRecord& serviceRecord : m_driverServiceCache)
    {
        const bool matchFilter =
            filterText.isEmpty() ||
            serviceRecord.serviceName.contains(filterText, Qt::CaseInsensitive) ||
            serviceRecord.displayName.contains(filterText, Qt::CaseInsensitive) ||
            serviceRecord.binaryPath.contains(filterText, Qt::CaseInsensitive) ||
            serviceRecord.description.contains(filterText, Qt::CaseInsensitive);
        if (!matchFilter)
        {
            continue;
        }

        const int rowIndex = m_serviceTable->rowCount();
        m_serviceTable->insertRow(rowIndex);

        QTableWidgetItem* serviceNameItem = createReadOnlyItem(serviceRecord.serviceName);
        serviceNameItem->setData(Qt::UserRole, serviceRecord.serviceName);
        m_serviceTable->setItem(rowIndex, 0, serviceNameItem);
        m_serviceTable->setItem(rowIndex, 1, createReadOnlyItem(serviceRecord.displayName));
        m_serviceTable->setItem(rowIndex, 2, createReadOnlyItem(serviceStateToText(serviceRecord.currentState)));
        m_serviceTable->setItem(rowIndex, 3, createReadOnlyItem(startTypeToText(serviceRecord.startType)));
        m_serviceTable->setItem(rowIndex, 4, createReadOnlyItem(errorControlToText(serviceRecord.errorControl)));

        QTableWidgetItem* pathItem = createReadOnlyItem(serviceRecord.binaryPath);
        pathItem->setToolTip(serviceRecord.binaryPath);
        m_serviceTable->setItem(rowIndex, 5, pathItem);

        QTableWidgetItem* descriptionItem = createReadOnlyItem(serviceRecord.description);
        descriptionItem->setToolTip(serviceRecord.description);
        m_serviceTable->setItem(rowIndex, 6, descriptionItem);

        if (serviceRecord.currentState == SERVICE_RUNNING)
        {
            for (int columnIndex = 0; columnIndex < m_serviceTable->columnCount(); ++columnIndex)
            {
                QTableWidgetItem* cellItem = m_serviceTable->item(rowIndex, columnIndex);
                if (cellItem != nullptr)
                {
                    cellItem->setBackground(KswordTheme::NewRowBackgroundColor());
                }
            }
        }
        ++visibleCount;
    }

    if (m_overviewStatusLabel != nullptr)
    {
        m_overviewStatusLabel->setText(
            driverText(
                "driver.service.count.filtered",
                QStringLiteral("状态：驱动服务 %1 条（显示 %2 条）"))
            .arg(m_driverServiceCache.size())
            .arg(visibleCount));
    }
}

void DriverDock::rebuildLoadedModuleTable()
{
    if (m_moduleTable == nullptr)
    {
        return;
    }

    // filterText 用途：仅筛选内核模块页，不再与驱动服务页共用搜索条件。
    const QString filterText = m_moduleFilterEdit != nullptr
        ? m_moduleFilterEdit->text().trimmed()
        : QString();
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_moduleEvidenceDetailEditor);
    m_moduleTable->setRowCount(0);
    for (std::size_t sourceIndex = 0U; sourceIndex < m_loadedModuleCache.size(); ++sourceIndex)
    {
        const LoadedKernelModuleRecord& moduleRecord = m_loadedModuleCache[sourceIndex];
        // evidencePointer 用途：签名后台扫描完成后让搜索立即覆盖签名状态文本。
        const LoadedModuleEvidenceRecord* evidencePointer =
            sourceIndex < m_loadedModuleEvidenceCache.size()
            ? &m_loadedModuleEvidenceCache[sourceIndex]
            : nullptr;
        const QString signatureStatusText = evidencePointer != nullptr
            ? moduleSignatureStatusText(*evidencePointer)
            : driverText("driver.evidence.pending", QStringLiteral("待扫描"));
        const bool matchesFilter =
            filterText.isEmpty() ||
            moduleRecord.moduleName.contains(filterText, Qt::CaseInsensitive) ||
            moduleRecord.imagePath.contains(filterText, Qt::CaseInsensitive) ||
            signatureStatusText.contains(filterText, Qt::CaseInsensitive);
        if (!matchesFilter)
        {
            continue;
        }

        const int rowIndex = m_moduleTable->rowCount();
        m_moduleTable->insertRow(rowIndex);
        QTableWidgetItem* moduleNameItem = createReadOnlyItem(moduleRecord.moduleName);
        moduleNameItem->setData(
            ModuleRecordIndexRole,
            QVariant::fromValue<qulonglong>(static_cast<qulonglong>(sourceIndex)));
        m_moduleTable->setItem(rowIndex, ModuleNameColumn, moduleNameItem);
        QTableWidgetItem* baseItem = createReadOnlyItem(formatAddress(moduleRecord.baseAddress));
        baseItem->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(
            static_cast<qulonglong>(moduleRecord.baseAddress)));
        m_moduleTable->setItem(rowIndex, ModuleBaseColumn, baseItem);
        m_moduleTable->setItem(
            rowIndex,
            ModuleSignatureColumn,
            createReadOnlyItem(signatureStatusText));
        for (int evidenceColumn = ModuleEvidenceFirstColumn;
            evidenceColumn <= ModuleEvidenceLastColumn;
            ++evidenceColumn)
        {
            m_moduleTable->setItem(
                rowIndex,
                evidenceColumn,
                createReadOnlyItem(driverText("driver.evidence.pending", QStringLiteral("待扫描"))));
        }
        QTableWidgetItem* pathItem = createReadOnlyItem(moduleRecord.imagePath);
        pathItem->setToolTip(moduleRecord.imagePath);
        m_moduleTable->setItem(rowIndex, ModuleImagePathColumn, pathItem);
    }
    if (m_moduleTable->rowCount() > 0)
    {
        m_moduleTable->setCurrentCell(0, 0);
    }
    rebuildLoadedModuleEvidenceViews();
    if (m_overviewStatusLabel != nullptr)
    {
        // visibleServiceCount 用途：状态栏同步展示服务与模块两个表格的筛选数量。
        const int visibleServiceCount = m_serviceTable != nullptr
            ? m_serviceTable->rowCount()
            : 0;
        m_overviewStatusLabel->setText(
            driverText(
                "driver.overview.count.filtered",
                QStringLiteral("状态：驱动服务 %1 条（显示 %2 条），模块 %3 条（显示 %4 条）"))
            .arg(m_driverServiceCache.size())
            .arg(visibleServiceCount)
            .arg(m_loadedModuleCache.size())
            .arg(m_moduleTable->rowCount()));
    }
}

void DriverDock::syncOperateFormBySelectedService()
{
    if (m_serviceTable == nullptr || m_serviceTable->selectionModel() == nullptr)
    {
        return;
    }

    const QModelIndexList rowList = m_serviceTable->selectionModel()->selectedRows(0);
    if (rowList.isEmpty())
    {
        return;
    }

    const int rowIndex = rowList.front().row();
    QTableWidgetItem* serviceNameItem = m_serviceTable->item(rowIndex, 0);
    if (serviceNameItem == nullptr)
    {
        return;
    }

    const QString serviceNameText = serviceNameItem->data(Qt::UserRole).toString();
    auto iterator = std::find_if(
        m_driverServiceCache.begin(),
        m_driverServiceCache.end(),
        [&serviceNameText](const DriverServiceRecord& record)
        {
            return record.serviceName.compare(serviceNameText, Qt::CaseInsensitive) == 0;
        });
    if (iterator == m_driverServiceCache.end())
    {
        return;
    }

    if (m_serviceNameEdit != nullptr)
    {
        m_serviceNameEdit->setText(iterator->serviceName);
    }
    if (m_displayNameEdit != nullptr)
    {
        m_displayNameEdit->setText(iterator->displayName);
    }
    if (m_binaryPathEdit != nullptr)
    {
        m_binaryPathEdit->setText(trimQuotedText(iterator->binaryPath));
    }
    if (m_descriptionEdit != nullptr)
    {
        m_descriptionEdit->setText(iterator->description);
    }

    if (m_startTypeCombo != nullptr)
    {
        const int startTypeIndex = m_startTypeCombo->findData(static_cast<int>(iterator->startType));
        if (startTypeIndex >= 0)
        {
            m_startTypeCombo->setCurrentIndex(startTypeIndex);
        }
    }
    if (m_errorControlCombo != nullptr)
    {
        const int errorControlIndex = m_errorControlCombo->findData(static_cast<int>(iterator->errorControl));
        if (errorControlIndex >= 0)
        {
            m_errorControlCombo->setCurrentIndex(errorControlIndex);
        }
    }
}

void DriverDock::refreshSelectedServiceStateToForm()
{
    if (m_serviceNameEdit == nullptr)
    {
        return;
    }

    kLogEvent queryEvent;
    const QString serviceNameText = m_serviceNameEdit->text().trimmed();
    if (serviceNameText.isEmpty())
    {
        appendOperateLogLine(
            driverText("driver.operation.query.empty_name", QStringLiteral("查询失败：服务名不能为空。")));
        warn << queryEvent
            << driverText("driver.log.query.empty_name", QStringLiteral("[DriverDock] 查询状态失败：服务名为空。"))
            << eol;
        return;
    }

    // UI adapter only: the reusable service layer owns SCM open/query/close details.
    ks::service::ServiceStatus statusInfo;
    std::string errorText;
    std::uint32_t errorCode = 0;
    if (!ks::service::QueryServiceStatus(
        toWideString(serviceNameText),
        &statusInfo,
        &errorText,
        &errorCode))
    {
        appendOperateLogLine(
            driverText("driver.operation.query.failed", QStringLiteral("查询失败：%1"))
            .arg(QString::fromUtf8(errorText.c_str())));
        warn << queryEvent
            << driverText("driver.log.query.failed", QStringLiteral("[DriverDock] 查询状态失败, service="))
            << serviceNameText.toStdString()
            << ", error=" << errorCode
            << ", detail=" << errorText
            << eol;
        return;
    }

    appendOperateLogLine(
        driverText("driver.operation.query.status", QStringLiteral("服务 %1 当前状态：%2"))
        .arg(serviceNameText)
        .arg(serviceStateToText(statusInfo.currentState)));

    info << queryEvent
        << driverText("driver.log.query.succeeded", QStringLiteral("[DriverDock] 查询状态成功, service="))
        << serviceNameText.toStdString()
        << ", state=" << statusInfo.currentState
        << eol;
}


void DriverDock::registerOrUpdateDriverService()
{
    if (m_serviceNameEdit == nullptr ||
        m_binaryPathEdit == nullptr ||
        m_startTypeCombo == nullptr ||
        m_errorControlCombo == nullptr)
    {
        return;
    }

    kLogEvent operationEvent;
    const QString serviceNameText = m_serviceNameEdit->text().trimmed();
    const QString displayNameText = (m_displayNameEdit == nullptr)
        ? QString()
        : m_displayNameEdit->text().trimmed();
    const QString descriptionText = (m_descriptionEdit == nullptr)
        ? QString()
        : m_descriptionEdit->text().trimmed();
    const QString binaryPathText = normalizeDriverBinaryPath(m_binaryPathEdit->text().trimmed());

    if (serviceNameText.isEmpty())
    {
        appendOperateLogLine(
            driverText("driver.operation.register.empty_service", QStringLiteral("注册/更新失败：服务名不能为空。")));
        warn << operationEvent
            << driverText("driver.log.register.empty_service", QStringLiteral("[DriverDock] 注册/更新失败：服务名为空。"))
            << eol;
        return;
    }
    if (binaryPathText.isEmpty())
    {
        appendOperateLogLine(
            driverText("driver.operation.register.empty_path", QStringLiteral("注册/更新失败：驱动路径不能为空。")));
        warn << operationEvent
            << driverText("driver.log.register.empty_path", QStringLiteral("[DriverDock] 注册/更新失败：路径为空。"))
            << eol;
        return;
    }

    const QString unquotedPathText = trimQuotedText(binaryPathText);
    if (!QFileInfo::exists(unquotedPathText) &&
        !unquotedPathText.startsWith(QStringLiteral("\\SystemRoot\\"), Qt::CaseInsensitive) &&
        !unquotedPathText.startsWith(QStringLiteral("%SystemRoot%"), Qt::CaseInsensitive))
    {
        appendOperateLogLine(
            driverText(
                "driver.operation.register.path_unavailable",
                QStringLiteral("警告：驱动路径当前不可访问，仍将尝试注册。")));
    }

    ks::service::KernelDriverServiceConfig serviceConfig;
    serviceConfig.serviceName = toWideString(serviceNameText);
    serviceConfig.displayName = toWideString(displayNameText);
    serviceConfig.description = toWideString(descriptionText);
    serviceConfig.binaryPath = toWideString(binaryPathText);
    serviceConfig.startType = static_cast<std::uint32_t>(m_startTypeCombo->currentData().toInt());
    serviceConfig.errorControl = static_cast<std::uint32_t>(m_errorControlCombo->currentData().toInt());

    bool created = false;
    std::string errorText;
    std::uint32_t errorCode = 0;
    if (!ks::service::CreateOrUpdateKernelDriverService(
        serviceConfig,
        &created,
        &errorText,
        &errorCode))
    {
        (void)ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("注册或更新驱动服务"),
            errorCode);
        appendOperateLogLine(
            driverText("driver.operation.register.failed", QStringLiteral("注册/更新失败：%1"))
            .arg(QString::fromUtf8(errorText.c_str())));
        err << operationEvent
            << driverText("driver.log.register.failed", QStringLiteral("[DriverDock] 注册/更新失败, service="))
            << serviceNameText.toStdString()
            << ", error=" << errorCode
            << ", detail=" << errorText
            << eol;
        return;
    }

    appendOperateLogLine(
        driverText("driver.operation.register.succeeded", QStringLiteral("%1成功：service=%2"))
        .arg(created
            ? driverText("driver.operation.register.created", QStringLiteral("注册"))
            : driverText("driver.operation.register.updated", QStringLiteral("更新")))
        .arg(serviceNameText));

    info << operationEvent
        << driverText("driver.log.register.succeeded", QStringLiteral("[DriverDock] 注册/更新成功, created="))
        << (created ? "true" : "false")
        << ", service=" << serviceNameText.toStdString()
        << eol;

    refreshDriverServiceRecords();
}


void DriverDock::loadSelectedDriverService()
{
    // 挂载驱动服务：
    // - 入参：无；服务名与镜像路径取自操作页输入框，下发前完成快照；
    // - 处理：StartServiceW 会同步等待 DriverEntry 返回，并在内部轮询最长 6 秒，
    //   因此整段 SCM 调用放到线程池，UI 线程只保留输入校验、按钮禁用与结果落地；
    // - 返回：无返回值；结果通过操作日志、权限提示与随后的服务/模块刷新体现。
    if (m_serviceNameEdit == nullptr)
    {
        return;
    }

    kLogEvent operationEvent;
    const QString serviceNameText = m_serviceNameEdit->text().trimmed();
    if (serviceNameText.isEmpty())
    {
        appendOperateLogLine(
            driverText("driver.operation.load.empty_name", QStringLiteral("挂载失败：服务名不能为空。")));
        warn << operationEvent
            << driverText("driver.log.load.empty_name", QStringLiteral("[DriverDock] 挂载失败：服务名为空。"))
            << eol;
        return;
    }

    // 忙标记 + 按钮禁用：挂载/卸载/删除针对同一服务，后台执行期间不允许重复下发。
    if (!tryBeginDriverServiceControlOperation(this))
    {
        return;
    }
    setDriverServiceControlButtonsEnabled(
        m_loadDriverButton,
        m_unloadDriverButton,
        m_deleteServiceButton,
        false);

    const QString binaryPathText =
        (m_binaryPathEdit == nullptr) ? QString() : m_binaryPathEdit->text().trimmed();
    const std::wstring serviceNameWide = toWideString(serviceNameText);
    const QPointer<DriverDock> guardThis(this);
    QRunnable* loadTask = QRunnable::create(
        [guardThis, operationEvent, serviceNameText, binaryPathText, serviceNameWide]()
        {
            ks::service::ServiceStatus finalStatus{};
            std::string errorText;
            std::uint32_t errorCode = 0U;
            const bool startSucceeded = ks::service::StartServiceByName(
                serviceNameWide,
                6000,
                SERVICE_RUNNING,
                &finalStatus,
                &errorText,
                &errorCode);

            QCoreApplication* const applicationInstance = QCoreApplication::instance();
            if (applicationInstance == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                applicationInstance,
                [guardThis,
                 operationEvent,
                 serviceNameText,
                 binaryPathText,
                 startSucceeded,
                 finalStatus,
                 errorText,
                 errorCode]()
                {
                    if (guardThis.isNull())
                    {
                        return;
                    }
                    endDriverServiceControlOperation(guardThis.data());
                    setDriverServiceControlButtonsEnabled(
                        guardThis->m_loadDriverButton,
                        guardThis->m_unloadDriverButton,
                        guardThis->m_deleteServiceButton,
                        true);

                    if (!startSucceeded)
                    {
                        (void)ks::ui::promptForPrivilegeFailure(
                            guardThis,
                            QStringLiteral("挂载驱动服务"),
                            errorCode);
                        if (isDriverSignatureLoadError(static_cast<DWORD>(errorCode)))
                        {
                            const QString adviceText = buildDriverSignatureLoadAdvice(
                                static_cast<DWORD>(errorCode),
                                serviceNameText,
                                binaryPathText);
                            guardThis->appendOperateLogLine(adviceText);
                            err << operationEvent
                                << driverText(
                                    "driver.log.load.signature_failed",
                                    QStringLiteral("[DriverDock] 挂载失败：驱动签名/镜像校验失败, service="))
                                << serviceNameText.toStdString()
                                << ", error=" << errorCode
                                << ", path=" << binaryPathText.toStdString()
                                << eol;
                            return;
                        }

                        guardThis->appendOperateLogLine(
                            driverText("driver.operation.load.failed", QStringLiteral("挂载失败：%1"))
                            .arg(QString::fromUtf8(errorText.c_str())));
                        err << operationEvent
                            << driverText(
                                "driver.log.load.failed",
                                QStringLiteral("[DriverDock] 挂载失败, service="))
                            << serviceNameText.toStdString()
                            << ", error=" << errorCode
                            << ", detail=" << errorText
                            << eol;
                        return;
                    }

                    guardThis->appendOperateLogLine(finalStatus.currentState == SERVICE_RUNNING
                        ? driverText("driver.operation.load.success", QStringLiteral("挂载成功：service=%1"))
                            .arg(serviceNameText)
                        : driverText("driver.operation.load.completed", QStringLiteral("挂载结束：当前状态=%1"))
                            .arg(guardThis->serviceStateToText(finalStatus.currentState)));

                    info << operationEvent
                        << driverText(
                            "driver.log.load.completed",
                            QStringLiteral("[DriverDock] 挂载执行完成, service="))
                        << serviceNameText.toStdString()
                        << ", finalState=" << finalStatus.currentState
                        << eol;

                    guardThis->refreshDriverServiceRecords();
                    guardThis->refreshLoadedKernelModuleRecords();
                },
                Qt::QueuedConnection);
        });
    loadTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(loadTask);
}


void DriverDock::unloadSelectedDriverService()
{
    // 卸载驱动服务：
    // - 入参：无；服务名取自操作页输入框，下发前完成快照；
    // - 处理：ControlService(SERVICE_CONTROL_STOP) 会同步执行目标 DriverUnload，
    //   并在内部轮询最长 6 秒，因此整段 SCM 调用放到线程池，UI 线程只留校验与结果落地；
    // - 返回：无返回值；结果通过操作日志、权限提示与随后的服务/模块刷新体现。
    if (m_serviceNameEdit == nullptr)
    {
        return;
    }

    kLogEvent operationEvent;
    const QString serviceNameText = m_serviceNameEdit->text().trimmed();
    if (serviceNameText.isEmpty())
    {
        appendOperateLogLine(
            driverText("driver.operation.unload.empty_name", QStringLiteral("卸载失败：服务名不能为空。")));
        warn << operationEvent
            << driverText("driver.log.unload.empty_name", QStringLiteral("[DriverDock] 卸载失败：服务名为空。"))
            << eol;
        return;
    }

    // 忙标记 + 按钮禁用：挂载/卸载/删除针对同一服务，后台执行期间不允许重复下发。
    if (!tryBeginDriverServiceControlOperation(this))
    {
        return;
    }
    setDriverServiceControlButtonsEnabled(
        m_loadDriverButton,
        m_unloadDriverButton,
        m_deleteServiceButton,
        false);

    const std::wstring serviceNameWide = toWideString(serviceNameText);
    const QPointer<DriverDock> guardThis(this);
    QRunnable* unloadTask = QRunnable::create(
        [guardThis, operationEvent, serviceNameText, serviceNameWide]()
        {
            ks::service::ServiceStatus finalStatus{};
            std::string errorText;
            std::uint32_t errorCode = 0U;
            const bool stopSucceeded = ks::service::StopServiceByName(
                serviceNameWide,
                6000,
                SERVICE_STOPPED,
                &finalStatus,
                &errorText,
                &errorCode);

            QCoreApplication* const applicationInstance = QCoreApplication::instance();
            if (applicationInstance == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                applicationInstance,
                [guardThis,
                 operationEvent,
                 serviceNameText,
                 stopSucceeded,
                 finalStatus,
                 errorText,
                 errorCode]()
                {
                    if (guardThis.isNull())
                    {
                        return;
                    }
                    endDriverServiceControlOperation(guardThis.data());
                    setDriverServiceControlButtonsEnabled(
                        guardThis->m_loadDriverButton,
                        guardThis->m_unloadDriverButton,
                        guardThis->m_deleteServiceButton,
                        true);

                    if (!stopSucceeded)
                    {
                        (void)ks::ui::promptForPrivilegeFailure(
                            guardThis,
                            QStringLiteral("卸载驱动服务"),
                            errorCode);
                        guardThis->appendOperateLogLine(
                            driverText("driver.operation.unload.failed", QStringLiteral("卸载失败：%1"))
                            .arg(QString::fromUtf8(errorText.c_str())));
                        err << operationEvent
                            << driverText(
                                "driver.log.unload.failed",
                                QStringLiteral("[DriverDock] 卸载失败, service="))
                            << serviceNameText.toStdString()
                            << ", error=" << errorCode
                            << ", detail=" << errorText
                            << eol;
                        return;
                    }

                    guardThis->appendOperateLogLine(finalStatus.currentState == SERVICE_STOPPED
                        ? driverText("driver.operation.unload.success", QStringLiteral("卸载成功：service=%1"))
                            .arg(serviceNameText)
                        : driverText("driver.operation.unload.completed", QStringLiteral("卸载结束：当前状态=%1"))
                            .arg(guardThis->serviceStateToText(finalStatus.currentState)));

                    info << operationEvent
                        << driverText(
                            "driver.log.unload.completed",
                            QStringLiteral("[DriverDock] 卸载执行完成, service="))
                        << serviceNameText.toStdString()
                        << ", finalState=" << finalStatus.currentState
                        << eol;

                    guardThis->refreshDriverServiceRecords();
                    guardThis->refreshLoadedKernelModuleRecords();
                },
                Qt::QueuedConnection);
        });
    unloadTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(unloadTask);
}


void DriverDock::deleteSelectedDriverService()
{
    // 删除驱动服务注册：
    // - 入参：无；服务名取自操作页输入框，下发前完成快照；
    // - 处理：DeleteServiceByName 会先尝试停服并轮询等待最长 4 秒，随后调用 DeleteService，
    //   整段 SCM 调用放到线程池，UI 线程只留校验、按钮禁用与结果落地；
    // - 返回：无返回值；结果通过操作日志、权限提示与随后的服务/模块刷新体现。
    if (m_serviceNameEdit == nullptr)
    {
        return;
    }

    kLogEvent operationEvent;
    const QString serviceNameText = m_serviceNameEdit->text().trimmed();
    if (serviceNameText.isEmpty())
    {
        appendOperateLogLine(
            driverText("driver.operation.delete.empty_name", QStringLiteral("删除失败：服务名不能为空。")));
        warn << operationEvent
            << driverText("driver.log.delete.empty_name", QStringLiteral("[DriverDock] 删除失败：服务名为空。"))
            << eol;
        return;
    }

    // 忙标记 + 按钮禁用：挂载/卸载/删除针对同一服务，后台执行期间不允许重复下发。
    if (!tryBeginDriverServiceControlOperation(this))
    {
        return;
    }
    setDriverServiceControlButtonsEnabled(
        m_loadDriverButton,
        m_unloadDriverButton,
        m_deleteServiceButton,
        false);

    const std::wstring serviceNameWide = toWideString(serviceNameText);
    const QPointer<DriverDock> guardThis(this);
    QRunnable* deleteTask = QRunnable::create(
        [guardThis, operationEvent, serviceNameText, serviceNameWide]()
        {
            std::string errorText;
            std::uint32_t errorCode = 0U;
            const bool deleteSucceeded = ks::service::DeleteServiceByName(
                serviceNameWide,
                true,
                4000,
                &errorText,
                &errorCode);

            QCoreApplication* const applicationInstance = QCoreApplication::instance();
            if (applicationInstance == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                applicationInstance,
                [guardThis,
                 operationEvent,
                 serviceNameText,
                 deleteSucceeded,
                 errorText,
                 errorCode]()
                {
                    if (guardThis.isNull())
                    {
                        return;
                    }
                    endDriverServiceControlOperation(guardThis.data());
                    setDriverServiceControlButtonsEnabled(
                        guardThis->m_loadDriverButton,
                        guardThis->m_unloadDriverButton,
                        guardThis->m_deleteServiceButton,
                        true);

                    if (!deleteSucceeded)
                    {
                        (void)ks::ui::promptForPrivilegeFailure(
                            guardThis,
                            QStringLiteral("删除驱动服务"),
                            errorCode);
                        guardThis->appendOperateLogLine(
                            driverText("driver.operation.delete.failed", QStringLiteral("删除失败：%1"))
                            .arg(QString::fromUtf8(errorText.c_str())));
                        err << operationEvent
                            << driverText(
                                "driver.log.delete.failed",
                                QStringLiteral("[DriverDock] 删除失败, service="))
                            << serviceNameText.toStdString()
                            << ", error=" << errorCode
                            << ", detail=" << errorText
                            << eol;
                        return;
                    }

                    guardThis->appendOperateLogLine(
                        driverText(
                            "driver.operation.delete.succeeded",
                            QStringLiteral("删除成功（或已标记删除）：service=%1"))
                        .arg(serviceNameText));
                    info << operationEvent
                        << driverText(
                            "driver.log.delete.completed",
                            QStringLiteral("[DriverDock] 删除执行完成, service="))
                        << serviceNameText.toStdString() << eol;
                    guardThis->refreshDriverServiceRecords();
                    guardThis->refreshLoadedKernelModuleRecords();
                },
                Qt::QueuedConnection);
        });
    deleteTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(deleteTask);
}
