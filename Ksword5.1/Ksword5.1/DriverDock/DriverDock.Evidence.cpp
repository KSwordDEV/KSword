#include "DriverDock.Internal.h"
#include "../OnlineScan/SandboxUploadActions.h"
#include "../UI/TableInteractionSupport.h"

#include <Windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <mscat.h>
#include <Softpub.h>
#include <WinTrust.h>

#include <QByteArray>

#pragma comment(lib, "Wintrust.lib")

using namespace ksword::driver_dock_internal;

namespace
{
    class DriverEvidenceSourceTextScope final
    {
    public:
        DriverEvidenceSourceTextScope()
            : m_previousMode(swapDriverEvidenceSourceTextMode(true))
        {
        }

        ~DriverEvidenceSourceTextScope()
        {
            swapDriverEvidenceSourceTextMode(m_previousMode);
        }

        DriverEvidenceSourceTextScope(const DriverEvidenceSourceTextScope&) = delete;
        DriverEvidenceSourceTextScope& operator=(const DriverEvidenceSourceTextScope&) = delete;

    private:
        bool m_previousMode = false;
    };

    // EvidenceModuleKey：模块证据聚合使用的小写模块名 key。
    // 输入：模块名或路径叶子名；处理：去空白、取文件名、小写；返回：稳定比较 key。
    QString evidenceModuleKey(QString moduleNameText)
    {
        moduleNameText = moduleNameText.trimmed();
        const int slashIndex = std::max(moduleNameText.lastIndexOf(QLatin1Char('\\')), moduleNameText.lastIndexOf(QLatin1Char('/')));
        if (slashIndex >= 0 && slashIndex + 1 < moduleNameText.size())
        {
            moduleNameText = moduleNameText.mid(slashIndex + 1);
        }
        return moduleNameText.toLower();
    }

    // evidenceModuleStem：从 xxx.sys 生成 xxx，用作 DriverObject 名称候选。
    // 输入：模块文件名；处理：提取叶子名并裁掉 .sys 后缀；返回：候选对象叶子名。
    QString evidenceModuleStem(const QString& moduleNameText)
    {
        QString stemText = evidenceModuleKey(moduleNameText);
        if (stemText.endsWith(QStringLiteral(".sys"), Qt::CaseInsensitive))
        {
            stemText.chop(4);
        }
        return stemText.trimmed();
    }

    // evidenceYesNo：把证据布尔值转为短中文文本。
    // 输入：flag 表示命中或未命中；处理：选择两个中文短语；返回：单元格显示文本。
    QString evidenceYesNo(const bool flag, const QString& yesText, const QString& noText)
    {
        return flag ? yesText : noText;
    }

    // evidenceHookStatusText：把内核 Hook 状态转为 DriverDock 证据文本。
    // 输入：R0 共享协议状态；处理：按共享常量映射；返回：中文状态文本。
    QString evidenceHookStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_KERNEL_HOOK_STATUS_CLEAN:
            return driverText("driver.evidence.hook.clean", QStringLiteral("干净"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS:
            return driverText("driver.evidence.hook.suspicious_external", QStringLiteral("可疑外跳"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_INTERNAL_BRANCH:
            return driverText("driver.evidence.hook.internal_branch", QStringLiteral("模块内跳转"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_READ_FAILED:
            return driverText("driver.evidence.hook.read_failed", QStringLiteral("读取失败"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_PARSE_FAILED:
            return driverText("driver.evidence.hook.parse_failed", QStringLiteral("解析失败"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_FORCE_REQUIRED:
            return driverText("driver.evidence.hook.force_required", QStringLiteral("需要强制确认"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_PATCHED:
            return driverText("driver.evidence.hook.patched", QStringLiteral("已修复/摘除"));
        case KSWORD_ARK_KERNEL_HOOK_STATUS_PATCH_FAILED:
            return driverText("driver.evidence.hook.patch_failed", QStringLiteral("修复失败"));
        default:
            return driverText("driver.evidence.hook.unknown", QStringLiteral("未知(%1)")).arg(statusValue);
        }
    }

    // evidenceInlineHookTypeText：把 Inline Hook 类型转为简短文本。
    // 输入：共享协议 hookType；处理：映射常见跳转/补丁形态；返回：中文/汇编文本。
    QString evidenceInlineHookTypeText(const std::uint32_t hookType)
    {
        switch (hookType)
        {
        case KSWORD_ARK_INLINE_HOOK_TYPE_NONE:
            return driverText("driver.evidence.inline.none", QStringLiteral("无明显补丁"));
        case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_REL32:
            return QStringLiteral("JMP rel32");
        case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_REL8:
            return QStringLiteral("JMP rel8");
        case KSWORD_ARK_INLINE_HOOK_TYPE_JMP_RIP_INDIRECT:
            return QStringLiteral("JMP [RIP+rel32]");
        case KSWORD_ARK_INLINE_HOOK_TYPE_MOV_RAX_JMP_RAX:
            return QStringLiteral("MOV RAX; JMP RAX");
        case KSWORD_ARK_INLINE_HOOK_TYPE_MOV_R11_JMP_R11:
            return QStringLiteral("MOV R11; JMP R11");
        case KSWORD_ARK_INLINE_HOOK_TYPE_RET_PATCH:
            return driverText("driver.evidence.inline.ret_patch", QStringLiteral("RET 补丁"));
        case KSWORD_ARK_INLINE_HOOK_TYPE_INT3_PATCH:
            return driverText("driver.evidence.inline.int3_patch", QStringLiteral("INT3 补丁"));
        case KSWORD_ARK_INLINE_HOOK_TYPE_UNKNOWN_PATCH:
            return driverText("driver.evidence.inline.unknown_patch", QStringLiteral("未知补丁"));
        default:
            return driverText("driver.evidence.inline.unknown", QStringLiteral("未知(%1)")).arg(hookType);
        }
    }

    // evidenceIatEatClassText：把 IAT/EAT 类型转成详情文本。
    // 输入：共享协议 hookClass；处理：映射 IAT 或 EAT；返回：中文类别文本。
    QString evidenceIatEatClassText(const std::uint32_t hookClass)
    {
        switch (hookClass)
        {
        case KSWORD_ARK_IAT_EAT_HOOK_CLASS_IAT:
            return QStringLiteral("IAT");
        case KSWORD_ARK_IAT_EAT_HOOK_CLASS_EAT:
            return QStringLiteral("EAT");
        default:
            return driverText("driver.evidence.iat_eat.unknown", QStringLiteral("未知(%1)")).arg(hookClass);
        }
    }

    // evidenceCallbackClassText：把 Callback 类别转成详情文本。
    // 输入：共享协议 callbackClass；处理：映射已知回调类型；返回：中文类别文本。
    QString evidenceCallbackClassText(const std::uint32_t callbackClass)
    {
        switch (callbackClass)
        {
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY:
            return driverText("driver.evidence.callback.class.registry", QStringLiteral("注册表 CmCallback"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS:
            return driverText("driver.evidence.callback.class.process", QStringLiteral("进程 Notify"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD:
            return driverText("driver.evidence.callback.class.thread", QStringLiteral("线程 Notify"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE:
            return driverText("driver.evidence.callback.class.image", QStringLiteral("镜像加载 Notify"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT:
            return QStringLiteral("Object Callback");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER:
            return QStringLiteral("Minifilter");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT:
            return QStringLiteral("WFP Callout");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER:
            return QStringLiteral("ETW Provider/Consumer");
        default:
            return driverText("driver.evidence.callback.class.unknown", QStringLiteral("未知(%1)")).arg(callbackClass);
        }
    }

    // evidenceCallbackStatusText：把 Callback 枚举状态转成详情文本。
    // 输入：共享协议 status 和 NTSTATUS；处理：保留失败码；返回：中文状态文本。
    QString evidenceCallbackStatusText(const std::uint32_t statusValue, const long lastStatus)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_OK:
            return driverText("driver.evidence.callback.status.ok", QStringLiteral("可见/成功"));
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED:
            return driverText("driver.evidence.callback.status.not_registered", QStringLiteral("未注册"));
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED:
            return driverText("driver.evidence.callback.status.unsupported", QStringLiteral("当前不支持"));
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED:
            return driverText("driver.evidence.callback.status.query_failed", QStringLiteral("查询失败(%1)"))
                .arg(formatNtStatusText(lastStatus));
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_BUFFER_TRUNCATED:
            return driverText("driver.evidence.callback.status.truncated", QStringLiteral("缓冲截断"));
        default:
            return driverText("driver.evidence.callback.status.unknown", QStringLiteral("未知(%1)"))
                .arg(statusValue);
        }
    }

    // evidenceAppendIoSummary：统一记录 ArkDriverClient 调用摘要。
    // 输入：标题、IoResult、输出列表；处理：追加一行可复制诊断；返回：无。
    void evidenceAppendIoSummary(
        QStringList& detailLines,
        const QString& titleText,
        const ksword::ark::IoResult& ioResult)
    {
        detailLines << QStringLiteral("[%1]").arg(titleText);
        detailLines << driverText("driver.evidence.io_summary", QStringLiteral("ok=%1 win32=%2 nt=%3 bytes=%4 说明=%5"))
            .arg(ioResult.ok ? QStringLiteral("true") : QStringLiteral("false"))
            .arg(ioResult.win32Error)
            .arg(formatNtStatusText(ioResult.ntStatus))
            .arg(ioResult.bytesReturned)
            .arg(describeDriverCollection(ioResult));
    }

    // evidenceModuleNameMatches：判断 R0 返回模块名是否对应目标模块。
    // 输入：R0 模块名、目标模块名；处理：取叶子名小写比较；返回：true 表示同模块。
    bool evidenceModuleNameMatches(const QString& leftText, const QString& rightText)
    {
        const QString leftKey = evidenceModuleKey(leftText);
        const QString rightKey = evidenceModuleKey(rightText);
        return !leftKey.isEmpty() && !rightKey.isEmpty() && leftKey == rightKey;
    }

    // evidenceAddressLooksInsideModule：用基址/大小兜底判断地址是否落在模块内。
    // 输入：地址、模块基址、模块大小；处理：开区间范围判断；返回：true 表示落在模块范围内。
    bool evidenceAddressLooksInsideModule(
        const std::uint64_t addressValue,
        const std::uint64_t moduleBase,
        const std::uint32_t moduleSize)
    {
        if (addressValue == 0U || moduleBase == 0U || moduleSize == 0U)
        {
            return false;
        }
        return addressValue >= moduleBase && addressValue < (moduleBase + moduleSize);
    }

    // evidenceCommunicationMaskForMajor：把 WDK MajorFunction 索引映射为 Issue #47 的五位协议掩码。
    // 输入：MajorFunction 数值；处理：仅识别本功能固定管理的五个通信槽；返回：对应掩码或 0。
    std::uint32_t evidenceCommunicationMaskForMajor(const std::uint32_t majorFunction)
    {
        switch (majorFunction)
        {
        case KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_INDEX_CREATE:
            return KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_CREATE;
        case KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_INDEX_READ:
            return KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_READ;
        case KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_INDEX_WRITE:
            return KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_WRITE;
        case KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_INDEX_DEVICE_CONTROL:
            return KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_DEVICE_CONTROL;
        case KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_INDEX_INTERNAL_DEVICE_CONTROL:
            return KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_INTERNAL_DEVICE_CONTROL;
        default:
            return 0U;
        }
    }

    // evidenceCommunicationMaskCount：计算五位通信槽掩码中的置位数。
    // 输入：共享协议掩码；处理：逐位清除最低置位；返回：置位数量。
    std::uint32_t evidenceCommunicationMaskCount(std::uint32_t maskValue)
    {
        std::uint32_t bitCount = 0U;
        while (maskValue != 0U)
        {
            maskValue &= (maskValue - 1U);
            ++bitCount;
        }
        return bitCount;
    }

    struct CatalogSignatureVerification
    {
        QString fileIdentifier;
        QString catalogPath;
        QString signerCertificateName;
        LONG trustStatus = 0;
        DWORD lookupError = ERROR_SUCCESS;
        bool trustStatusAvailable = false;
        bool trusted = false;
    };

    class CatalogAdminHandle final
    {
    public:
        CatalogAdminHandle() = default;

        ~CatalogAdminHandle()
        {
            if (value != nullptr)
            {
                ::CryptCATAdminReleaseContext(value, 0);
            }
        }

        CatalogAdminHandle(const CatalogAdminHandle&) = delete;
        CatalogAdminHandle& operator=(const CatalogAdminHandle&) = delete;

        HCATADMIN value = nullptr;
    };

    class ReadOnlyFileHandle final
    {
    public:
        explicit ReadOnlyFileHandle(const QString& filePath)
            : value(::CreateFileW(
                reinterpret_cast<LPCWSTR>(filePath.utf16()),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr))
        {
        }

        ~ReadOnlyFileHandle()
        {
            if (value != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(value);
            }
        }

        ReadOnlyFileHandle(const ReadOnlyFileHandle&) = delete;
        ReadOnlyFileHandle& operator=(const ReadOnlyFileHandle&) = delete;

        HANDLE value = INVALID_HANDLE_VALUE;
    };

    // initializeStrictTrustData：
    // - whole-chain 吊销检查覆盖完整证书链（根证书除外）；
    // - 仅使用本机缓存，离线、未知或链不完整时 WinVerifyTrust 必须返回失败。
    void initializeStrictTrustData(WINTRUST_DATA& trustData)
    {
        trustData = WINTRUST_DATA{};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        trustData.dwProvFlags =
            WTD_SAFER_FLAG |
            WTD_CACHE_ONLY_URL_RETRIEVAL |
            WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
            WTD_DISABLE_MD2_MD4;
    }

    // extractSignerCertificateName：
    // - 输入：WinVerifyTrust 在 VERIFY 阶段保留的 provider state；
    // - 处理：读取首个 signer chain 的叶证书 simple display name；
    // - 返回：最终签名证书名称，链状态不可读时为空。
    QString extractSignerCertificateName(const WINTRUST_DATA& trustData)
    {
        if (trustData.hWVTStateData == nullptr)
        {
            return QString();
        }

        CRYPT_PROVIDER_DATA* providerData =
            ::WTHelperProvDataFromStateData(trustData.hWVTStateData);
        if (providerData == nullptr)
        {
            return QString();
        }
        CRYPT_PROVIDER_SGNR* signer =
            ::WTHelperGetProvSignerFromChain(providerData, 0, FALSE, 0);
        if (signer == nullptr ||
            signer->csCertChain == 0 ||
            signer->pasCertChain == nullptr ||
            signer->pasCertChain[0].pCert == nullptr)
        {
            return QString();
        }

        const CERT_CONTEXT* certificateContext =
            signer->pasCertChain[0].pCert;
        const DWORD requiredChars = ::CertGetNameStringW(
            certificateContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            nullptr,
            nullptr,
            0);
        if (requiredChars <= 1)
        {
            return QString();
        }

        std::vector<wchar_t> nameBuffer(requiredChars, L'\0');
        const DWORD writtenChars = ::CertGetNameStringW(
            certificateContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            nullptr,
            nameBuffer.data(),
            requiredChars);
        if (writtenChars <= 1)
        {
            return QString();
        }
        return QString::fromWCharArray(
            nameBuffer.data(),
            static_cast<int>(writtenChars - 1)).trimmed();
    }

    // runWinTrustAndClose：所有 VERIFY 路径先提取叶证书名称，再执行 STATEACTION_CLOSE。
    LONG runWinTrustAndClose(
        WINTRUST_DATA& trustData,
        QString* const signerCertificateNameOut = nullptr)
    {
        GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        const LONG trustStatus = ::WinVerifyTrust(nullptr, &policyGuid, &trustData);
        if (signerCertificateNameOut != nullptr)
        {
            *signerCertificateNameOut =
                extractSignerCertificateName(trustData);
        }
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        ::WinVerifyTrust(nullptr, &policyGuid, &trustData);
        trustData.hWVTStateData = nullptr;
        return trustStatus;
    }

    bool calculateCatalogHash(
        const HCATADMIN catalogAdmin,
        const HANDLE fileHandle,
        std::vector<BYTE>& fileHash)
    {
        LARGE_INTEGER fileStart{};
        ::SetFilePointerEx(fileHandle, fileStart, nullptr, FILE_BEGIN);
        DWORD hashSize = 0U;
        if (!::CryptCATAdminCalcHashFromFileHandle2(
            catalogAdmin,
            fileHandle,
            &hashSize,
            nullptr,
            0) ||
            hashSize == 0U)
        {
            return false;
        }

        fileHash.resize(hashSize);
        ::SetFilePointerEx(fileHandle, fileStart, nullptr, FILE_BEGIN);
        const BOOL hashResult = ::CryptCATAdminCalcHashFromFileHandle2(
            catalogAdmin,
            fileHandle,
            &hashSize,
            fileHash.data(),
            0);
        if (hashResult == FALSE)
        {
            return false;
        }
        fileHash.resize(hashSize);
        return true;
    }

    CatalogSignatureVerification verifyCatalogSignature(
        const QString& normalizedPath,
        const HANDLE fileHandle)
    {
        CatalogSignatureVerification verification;
        CatalogAdminHandle catalogAdmin;
        GUID driverActionVerify = DRIVER_ACTION_VERIFY;
        if (!::CryptCATAdminAcquireContext2(
            &catalogAdmin.value,
            &driverActionVerify,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            0))
        {
            verification.lookupError = ::GetLastError();
            return verification;
        }

        std::vector<BYTE> fileHash;
        if (!calculateCatalogHash(catalogAdmin.value, fileHandle, fileHash))
        {
            verification.lookupError = ::GetLastError();
            return verification;
        }

        const QByteArray fileIdentifierBytes = QByteArray(
            reinterpret_cast<const char*>(fileHash.data()),
            static_cast<qsizetype>(fileHash.size()))
            .toHex()
            .toUpper();
        verification.fileIdentifier = QString::fromLatin1(
            fileIdentifierBytes.constData(),
            fileIdentifierBytes.size());

        HCATINFO previousCatalog = nullptr;
        for (;;)
        {
            HCATINFO currentCatalog = ::CryptCATAdminEnumCatalogFromHash(
                catalogAdmin.value,
                fileHash.data(),
                static_cast<DWORD>(fileHash.size()),
                0,
                &previousCatalog);
            if (currentCatalog == nullptr)
            {
                const DWORD enumerationError = ::GetLastError();
                verification.lookupError = enumerationError == ERROR_SUCCESS
                    ? ERROR_NOT_FOUND
                    : enumerationError;
                // 把 previous 传给下一次枚举时，API 接管并释放该 context；
                // 自然耗尽返回 nullptr 后调用方已不再拥有 HCATINFO。
                previousCatalog = nullptr;
                break;
            }
            previousCatalog = currentCatalog;

            CATALOG_INFO catalogInfo{};
            catalogInfo.cbStruct = sizeof(catalogInfo);
            if (!::CryptCATCatalogInfoFromContext(
                currentCatalog,
                &catalogInfo,
                0))
            {
                verification.lookupError = ::GetLastError();
                continue;
            }

            verification.catalogPath = QString::fromWCharArray(
                catalogInfo.wszCatalogFile);
            WINTRUST_CATALOG_INFO trustCatalogInfo{};
            trustCatalogInfo.cbStruct = sizeof(trustCatalogInfo);
            trustCatalogInfo.pcwszCatalogFilePath =
                reinterpret_cast<LPCWSTR>(verification.catalogPath.utf16());
            trustCatalogInfo.pcwszMemberTag =
                reinterpret_cast<LPCWSTR>(verification.fileIdentifier.utf16());
            trustCatalogInfo.pcwszMemberFilePath =
                reinterpret_cast<LPCWSTR>(normalizedPath.utf16());
            trustCatalogInfo.hMemberFile = fileHandle;
            trustCatalogInfo.pbCalculatedFileHash = fileHash.data();
            trustCatalogInfo.cbCalculatedFileHash =
                static_cast<DWORD>(fileHash.size());
            trustCatalogInfo.hCatAdmin = catalogAdmin.value;

            WINTRUST_DATA trustData{};
            initializeStrictTrustData(trustData);
            trustData.dwUnionChoice = WTD_CHOICE_CATALOG;
            trustData.pCatalog = &trustCatalogInfo;
            // Catalog provider 读取同一只读句柄前回到文件起点，不依赖哈希 API 留下的游标。
            LARGE_INTEGER fileStart{};
            ::SetFilePointerEx(fileHandle, fileStart, nullptr, FILE_BEGIN);
            verification.trustStatus = runWinTrustAndClose(
                trustData,
                &verification.signerCertificateName);
            verification.trustStatusAvailable = true;
            verification.trusted =
                verification.trustStatus == ERROR_SUCCESS;
            if (verification.trusted)
            {
                // 成功后提前结束枚举，按 mscat 契约显式释放最后一个 context。
                ::CryptCATAdminReleaseCatalogContext(
                    catalogAdmin.value,
                    currentCatalog,
                    0);
                previousCatalog = nullptr;
                verification.lookupError = ERROR_SUCCESS;
                break;
            }
        }
        return verification;
    }
}

DriverDock::LoadedModuleSignatureEvidence DriverDock::verifyLoadedModuleSignature(
    const QString& rawImagePath)
{
    LoadedModuleSignatureEvidence evidence;
    const QString normalizedPath =
        ks::online_scan::normalizeKernelImagePathForUpload(rawImagePath).trimmed();
    evidence.verificationPath =
        normalizedPath.isEmpty() ? rawImagePath : normalizedPath;
    if (normalizedPath.isEmpty() || !QFileInfo::exists(normalizedPath))
    {
        evidence.state = LoadedModuleSignatureState::PathUnavailable;
        return evidence;
    }

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath =
        reinterpret_cast<LPCWSTR>(normalizedPath.utf16());

    WINTRUST_DATA embeddedTrustData{};
    initializeStrictTrustData(embeddedTrustData);
    embeddedTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    embeddedTrustData.pFile = &fileInfo;
    const LONG embeddedTrustStatus = runWinTrustAndClose(
        embeddedTrustData,
        &evidence.signerCertificateName);
    evidence.embeddedTrustStatus =
        static_cast<std::int32_t>(embeddedTrustStatus);
    if (embeddedTrustStatus == ERROR_SUCCESS)
    {
        evidence.state = LoadedModuleSignatureState::TrustedEmbedded;
        return evidence;
    }

    // embedded 失败后必须继续查系统 Catalog，支持没有 PE 证书表的 catalog-only 驱动。
    evidence.catalogAttempted = true;
    ReadOnlyFileHandle fileHandle(normalizedPath);
    if (fileHandle.value == INVALID_HANDLE_VALUE)
    {
        evidence.catalogLookupError = ::GetLastError();
        evidence.state = LoadedModuleSignatureState::InvalidTrust;
        return evidence;
    }

    const CatalogSignatureVerification catalogVerification =
        verifyCatalogSignature(normalizedPath, fileHandle.value);
    evidence.fileIdentifier = catalogVerification.fileIdentifier;
    evidence.catalogPath = catalogVerification.catalogPath;
    evidence.signerCertificateName =
        catalogVerification.signerCertificateName;
    evidence.catalogTrustStatus =
        static_cast<std::int32_t>(catalogVerification.trustStatus);
    evidence.catalogLookupError = catalogVerification.lookupError;
    evidence.catalogTrustStatusAvailable =
        catalogVerification.trustStatusAvailable;
    evidence.state = catalogVerification.trusted
        ? LoadedModuleSignatureState::TrustedCatalog
        : LoadedModuleSignatureState::InvalidTrust;
    return evidence;
}

DriverDock::LoadedModuleEvidenceRecord DriverDock::buildPendingModuleEvidenceRecord(
    const LoadedKernelModuleRecord& moduleRecord)
{
    // 输入：模块记录；处理：填充各列等待文本；返回：占位证据记录。
    LoadedModuleEvidenceRecord evidence;
    evidence.moduleName = moduleRecord.moduleName;
    const QString pendingScanText = QStringLiteral("待扫描");
    evidence.driverObjectStatusText = pendingScanText;
    evidence.driverStartMatchText = pendingScanText;
    evidence.majorFunctionStatusText = pendingScanText;
    evidence.iatEatStatusText = pendingScanText;
    evidence.inlineHookStatusText = pendingScanText;
    evidence.callbackStatusText = pendingScanText;
    evidence.detailText = QStringLiteral(
        "模块 %1 尚未执行证据聚合。\n点击工具栏证据刷新按钮后，后台线程会只读查询 DriverObject / Hook / Callback。")
        .arg(moduleRecord.moduleName);
    return evidence;
}

QColor DriverDock::moduleEvidenceStatusColor(const LoadedModuleEvidenceRecord& evidence)
{
    // 输入：证据行；处理：错误/可疑/普通三档颜色；返回：QColor 前景色。
    if (!evidence.queryAttempted)
    {
        return KswordTheme::TextSecondaryColor();
    }
    if ((moduleSignatureCheckAttempted(evidence) &&
            !moduleSignatureTrusted(evidence)) ||
        evidence.hasMajorFunctionExternalJump ||
        evidence.hasIatEatSuspicious ||
        evidence.hasInlineHookSuspicious ||
        evidence.communicationConflict)
    {
        return KswordTheme::ErrorColor();
    }
    if (evidence.hasScanError ||
        !evidence.driverObjectResolved ||
        (evidence.driverStartKnown && !evidence.driverStartMatchesBase) ||
        evidence.hasCallbackReference ||
        evidence.communicationActive)
    {
        return KswordTheme::WarningColor();
    }
    return KswordTheme::SuccessColor();
}

bool DriverDock::moduleSignatureCheckAttempted(
    const LoadedModuleEvidenceRecord& evidence)
{
    return evidence.signatureEvidence.state !=
        LoadedModuleSignatureState::Pending;
}

bool DriverDock::moduleSignatureTrusted(
    const LoadedModuleEvidenceRecord& evidence)
{
    return evidence.signatureEvidence.state ==
            LoadedModuleSignatureState::TrustedEmbedded ||
        evidence.signatureEvidence.state ==
            LoadedModuleSignatureState::TrustedCatalog;
}

QString DriverDock::moduleSignatureStatusText(
    const LoadedModuleEvidenceRecord& evidence)
{
    if (!moduleSignatureCheckAttempted(evidence))
    {
        return driverText(
            "driver.evidence.pending",
            QStringLiteral("待扫描"));
    }
    if (!moduleSignatureTrusted(evidence))
    {
        return driverText(
            "driver.signature.invalid",
            QStringLiteral("无效"));
    }
    if (!evidence.signatureEvidence.signerCertificateName.isEmpty())
    {
        return evidence.signatureEvidence.signerCertificateName;
    }
    return driverText(
        "driver.signature.valid_signer_unknown",
        QStringLiteral("有效（签名者未知）"));
}

QString DriverDock::moduleSignatureDetailText(
    const LoadedModuleEvidenceRecord& evidence)
{
    const LoadedModuleSignatureEvidence& signature =
        evidence.signatureEvidence;
    const auto trustStatusHex = [](const std::int32_t statusValue)
    {
        return QString::number(
            static_cast<std::uint32_t>(statusValue),
            16)
            .rightJustified(8, QLatin1Char('0'))
            .toUpper();
    };
    const QString unavailableText = driverText(
        "driver.signature.not_available",
        QStringLiteral("<不可用>"));
    const QString verificationPath = signature.verificationPath.isEmpty()
        ? unavailableText
        : signature.verificationPath;
    const QString signerCertificateName =
        signature.signerCertificateName.isEmpty()
        ? unavailableText
        : signature.signerCertificateName;

    switch (signature.state)
    {
    case LoadedModuleSignatureState::Pending:
        return driverText(
            "driver.signature.pending.detail",
            QStringLiteral("数字签名信任链等待后台验证。"));
    case LoadedModuleSignatureState::PathUnavailable:
        return driverText(
            "driver.signature.path_unavailable",
            QStringLiteral("签名无效：模块映像路径不可访问。\n路径：%1"))
            .arg(verificationPath);
    case LoadedModuleSignatureState::TrustedEmbedded:
        return driverText(
            "driver.signature.valid.embedded.detail",
            QStringLiteral(
                "数字签名有效：Windows 已验证嵌入式 Authenticode 完整信任链。\n"
                "签名者：%1\n路径：%2\n验证方式：嵌入签名"))
            .arg(signerCertificateName)
            .arg(verificationPath);
    case LoadedModuleSignatureState::TrustedCatalog:
        return driverText(
            "driver.signature.valid.catalog.detail",
            QStringLiteral(
                "数字签名有效：Windows 已通过系统目录验证完整信任链。\n"
                "签名者：%1\n路径：%2\n验证方式：目录签名\n文件标识：%3\n目录：%4"))
            .arg(signerCertificateName)
            .arg(verificationPath)
            .arg(signature.fileIdentifier.isEmpty()
                ? unavailableText
                : signature.fileIdentifier)
            .arg(signature.catalogPath.isEmpty()
                ? unavailableText
                : signature.catalogPath);
    case LoadedModuleSignatureState::InvalidTrust:
    default:
        break;
    }

    const QString catalogTrustText =
        signature.catalogTrustStatusAvailable
        ? QStringLiteral("0x%1").arg(
            trustStatusHex(signature.catalogTrustStatus))
        : driverText(
            "driver.signature.not_performed",
            QStringLiteral("未执行"));
    const QString catalogLookupText = QStringLiteral("%1 (0x%2)")
        .arg(signature.catalogLookupError)
        .arg(
            QString::number(signature.catalogLookupError, 16)
                .rightJustified(8, QLatin1Char('0'))
                .toUpper());
    return driverText(
        "driver.signature.invalid.strict.detail",
        QStringLiteral(
            "数字签名无效或完整信任链无法验证。\n"
            "路径：%1\n"
            "嵌入式 WinVerifyTrust：0x%2\n"
            "目录 WinVerifyTrust：%3\n"
            "目录查询错误：%4\n"
            "文件标识：%5\n"
            "说明：吊销状态离线、未知或链不完整均按无效处理。"))
        .arg(verificationPath)
        .arg(trustStatusHex(signature.embeddedTrustStatus))
        .arg(catalogTrustText)
        .arg(catalogLookupText)
        .arg(signature.fileIdentifier.isEmpty()
            ? unavailableText
            : signature.fileIdentifier);
}

QString DriverDock::localizedModuleEvidenceText(const QString& sourceText)
{
    QStringList localizedLines;
    const QStringList sourceLines =
        sourceText.split(QLatin1Char('\n'), Qt::KeepEmptyParts);
    localizedLines.reserve(sourceLines.size());
    for (const QString& sourceLine : sourceLines)
    {
        localizedLines.push_back(ks::i18n::displayText(sourceLine));
    }
    return localizedLines.join(QLatin1Char('\n'));
}

bool DriverDock::queryDriverObjectForModuleEvidence(
    const LoadedKernelModuleRecord& moduleRecord,
    ksword::ark::DriverObjectQueryResult& resultOut,
    QString& attemptedNamesTextOut)
{
    // 输入：已加载模块行；处理：按常见 DriverObject 命名空间依次尝试查询；返回：是否解析成功。
    resultOut = ksword::ark::DriverObjectQueryResult{};
    attemptedNamesTextOut.clear();

    const QString stemText = evidenceModuleStem(moduleRecord.moduleName);
    if (stemText.isEmpty())
    {
        attemptedNamesTextOut = driverText("driver.evidence.module_name.empty", QStringLiteral("<模块名为空>"));
        return false;
    }

    const QStringList candidateNames = {
        QStringLiteral("\\Driver\\%1").arg(stemText),
        QStringLiteral("\\FileSystem\\%1").arg(stemText),
        QStringLiteral("\\FileSystem\\Filters\\%1").arg(stemText),
        stemText
    };

    QStringList attemptedNames;
    const ksword::ark::DriverClient driverClient;
    for (const QString& candidateName : candidateNames)
    {
        if (attemptedNames.contains(candidateName, Qt::CaseInsensitive))
        {
            continue;
        }
        attemptedNames << candidateName;

        const ksword::ark::DriverObjectQueryResult queryResult = driverClient.queryDriverObject(
            candidateName.toStdWString(),
            KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_MAJOR_FUNCTIONS |
                KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_NAMES,
            1UL,
            1UL);

        resultOut = queryResult;
        if (queryResult.io.ok &&
            (queryResult.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_OK ||
                queryResult.queryStatus == KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_PARTIAL) &&
            queryResult.driverObjectAddress != 0U)
        {
            attemptedNamesTextOut = attemptedNames.join(QStringLiteral(", "));
            return true;
        }
    }

    attemptedNamesTextOut = attemptedNames.join(QStringLiteral(", "));
    return false;
}

std::vector<DriverDock::LoadedModuleEvidenceRecord> DriverDock::collectEvidenceForLoadedModules(
    const std::vector<LoadedKernelModuleRecord>& moduleRecords)
{
    // 输入：当前模块快照；处理：调用现有 DriverClient 能力聚合证据；返回：与输入等长的证据数组。
    // 后台线程只缓存源文本和语义字段；LanguageManager 只允许 GUI 渲染阶段访问。
    const DriverEvidenceSourceTextScope sourceTextScope;
    std::vector<LoadedModuleEvidenceRecord> evidenceRecords;
    evidenceRecords.reserve(moduleRecords.size());

    const ksword::ark::DriverClient driverClient;
    const ksword::ark::KernelInlineHookScanResult inlineResult = driverClient.scanInlineHooks(
        0UL,
        KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES,
        std::wstring());
    const ksword::ark::KernelIatEatHookScanResult iatEatResult = driverClient.enumerateIatEatHooks(
        KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_IMPORTS | KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_EXPORTS,
        KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES,
        std::wstring());
    const ksword::ark::CallbackEnumResult callbackResult = driverClient.enumerateCallbacks(
        KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_ALL);

    for (const LoadedKernelModuleRecord& moduleRecord : moduleRecords)
    {
        LoadedModuleEvidenceRecord evidence = buildPendingModuleEvidenceRecord(moduleRecord);
        evidence.queryAttempted = true;
        // signatureVerification 用途：把模块文件的 Windows 信任链结论纳入同一后台证据快照。
        evidence.signatureEvidence =
            verifyLoadedModuleSignature(moduleRecord.imagePath);

        QStringList detailLines;

        ksword::ark::DriverObjectQueryResult objectResult;
        QString attemptedNamesText;
        evidence.driverObjectResolved = queryDriverObjectForModuleEvidence(
            moduleRecord,
            objectResult,
            attemptedNamesText);
        evidenceAppendIoSummary(
            detailLines,
            driverText("driver.evidence.detail.driver_object_query", QStringLiteral("DriverObject 查询")),
            objectResult.io);
        detailLines << driverText("driver.evidence.detail.candidate_names", QStringLiteral("候选名称: %1"))
            .arg(attemptedNamesText);
        detailLines << QStringLiteral("QueryStatus: %1").arg(driverObjectQueryStatusText(objectResult.queryStatus));
        detailLines << QStringLiteral("DriverName: %1").arg(QString::fromStdWString(objectResult.driverName));
        detailLines << QStringLiteral("DriverObject: %1").arg(formatCompactAddress(objectResult.driverObjectAddress));
        detailLines << QStringLiteral("DriverStart: %1").arg(formatCompactAddress(objectResult.driverStart));
        detailLines << QStringLiteral("DriverSize: 0x%1").arg(static_cast<qulonglong>(objectResult.driverSize), 8, 16, QChar('0')).toUpper();
        detailLines << QStringLiteral("ImagePath: %1").arg(QString::fromStdWString(objectResult.imagePath));
        detailLines << QString();

        evidence.driverObjectName = QString::fromStdWString(objectResult.driverName);
        evidence.driverObjectAddress = objectResult.driverObjectAddress;
        evidence.driverObjectStatusText = evidence.driverObjectResolved
            ? driverText("driver.evidence.status.resolved", QStringLiteral("已解析"))
            : driverText("driver.evidence.status.unresolved", QStringLiteral("未解析"));
        evidence.driverStartKnown = objectResult.driverStart != 0U;
        evidence.driverStartMatchesBase = evidence.driverStartKnown &&
            objectResult.driverStart == moduleRecord.baseAddress;
        evidence.driverStartMatchText = !evidence.driverStartKnown
            ? driverText("driver.evidence.status.unknown", QStringLiteral("未知"))
            : evidenceYesNo(
                evidence.driverStartMatchesBase,
                driverText("driver.evidence.status.match", QStringLiteral("匹配")),
                driverText("driver.evidence.status.mismatch", QStringLiteral("不匹配")));
        if (!objectResult.io.ok)
        {
            evidence.hasScanError = true;
        }

        ksword::ark::DriverCommunicationControlResult communicationResult;
        const bool communicationQueryEligible =
            evidence.driverObjectResolved &&
            evidence.driverStartMatchesBase &&
            evidence.driverObjectAddress != 0U &&
            !evidence.driverObjectName.trimmed().isEmpty();
        detailLines << driverText(
            "driver.evidence.communication.title",
            QStringLiteral("[IRP 通信控制]"));
        if (communicationQueryEligible)
        {
            communicationResult = driverClient.queryDriverCommunication(
                moduleRecord.baseAddress,
                evidence.driverObjectName.toStdWString());
            const bool operationSucceeded =
                communicationResult.io.ok &&
                communicationResult.lastStatus >= 0;
            const bool responseIdentityMatches =
                communicationResult.state ==
                    KSWORD_ARK_DRIVER_COMMUNICATION_STATE_INACTIVE ||
                (communicationResult.driverStart == moduleRecord.baseAddress &&
                    communicationResult.driverObjectAddress ==
                        evidence.driverObjectAddress);
            evidence.communicationStateKnown =
                operationSucceeded &&
                responseIdentityMatches;
            evidence.communicationActiveMask =
                evidence.communicationStateKnown
                ? communicationResult.activeMask
                : 0U;
            evidence.communicationOwnedMask =
                evidence.communicationStateKnown
                ? communicationResult.ownedMask
                : 0U;
            evidence.communicationConflictMask =
                evidence.communicationStateKnown
                ? communicationResult.conflictMask
                : 0U;
            evidence.communicationGeneration =
                evidence.communicationStateKnown
                ? communicationResult.generation
                : 0U;
            evidence.communicationRejectDispatchAddress =
                evidence.communicationStateKnown
                ? communicationResult.rejectDispatchAddress
                : 0U;
            evidence.communicationActive =
                evidence.communicationOwnedMask != 0U;
            evidence.communicationConflict =
                evidence.communicationConflictMask != 0U ||
                (evidence.communicationStateKnown &&
                    communicationResult.state ==
                        KSWORD_ARK_DRIVER_COMMUNICATION_STATE_CONFLICT);

            detailLines << driverText(
                "driver.evidence.communication.io",
                QStringLiteral("查询: ok=%1 Last=%2 说明=%3"))
                .arg(communicationResult.io.ok
                    ? QStringLiteral("true")
                    : QStringLiteral("false"))
                .arg(communicationResult.io.ok
                    ? formatNtStatusText(communicationResult.lastStatus)
                    : QStringLiteral("<不可用>"))
                .arg(describeDriverCollection(communicationResult.io));
            detailLines << driverText(
                "driver.evidence.communication.state",
                QStringLiteral(
                    "状态: known=%1 state=%2 active=%3 owned=%4 conflict=%5 generation=%6"))
                .arg(evidence.communicationStateKnown
                    ? QStringLiteral("true")
                    : QStringLiteral("false"))
                .arg(communicationResult.state)
                .arg(formatHex32(communicationResult.activeMask))
                .arg(formatHex32(communicationResult.ownedMask))
                .arg(formatHex32(communicationResult.conflictMask))
                .arg(communicationResult.generation);
            detailLines << driverText(
                "driver.evidence.communication.identity",
                QStringLiteral("身份: DriverObject=%1 DriverStart=%2 Reject=%3"))
                .arg(formatCompactAddress(
                    communicationResult.driverObjectAddress))
                .arg(formatCompactAddress(communicationResult.driverStart))
                .arg(formatCompactAddress(
                    communicationResult.rejectDispatchAddress));
            if (operationSucceeded && !responseIdentityMatches)
            {
                evidence.hasScanError = true;
                detailLines << driverText(
                    "driver.evidence.communication.identity_mismatch",
                    QStringLiteral(
                        "通信控制记录与当前 DriverObject 证据不一致，已拒绝把该记录视为可信状态。"));
            }
        }
        else
        {
            detailLines << driverText(
                "driver.evidence.communication.not_eligible",
                QStringLiteral(
                    "未查询：需要已解析的 canonical DriverObject、对象地址及匹配的 DriverStart。"));
        }
        detailLines << QString();

        detailLines << QStringLiteral("[MajorFunction]");
        if (objectResult.majorFunctions.empty())
        {
            detailLines << driverText(
                "driver.evidence.detail.major_function_missing",
                QStringLiteral("未返回 MajorFunction 表。")) << QString();
        }
        else
        {
            for (const ksword::ark::DriverMajorFunctionEntry& entry : objectResult.majorFunctions)
            {
                const bool outsideOwnImage = (entry.flags & 0x00000002U) == 0U;
                const std::uint32_t communicationMask =
                    evidenceCommunicationMaskForMajor(entry.majorFunction);
                const bool intentionalCommunicationBlind =
                    outsideOwnImage &&
                    evidence.communicationStateKnown &&
                    evidence.communicationRejectDispatchAddress != 0U &&
                    communicationMask != 0U &&
                    (evidence.communicationActiveMask & communicationMask) != 0U &&
                    (evidence.communicationOwnedMask & communicationMask) != 0U &&
                    entry.dispatchAddress ==
                        evidence.communicationRejectDispatchAddress;
                if (intentionalCommunicationBlind)
                {
                    ++evidence.majorFunctionIntentionalBlindCount;
                    detailLines << driverText(
                        "driver.evidence.detail.major_function_intentional_blind",
                        QStringLiteral(
                            "主动致盲: %1 dispatch=%2 系统拒绝入口，由 Issue #47 通信控制持有"))
                        .arg(driverMajorFunctionName(entry.majorFunction))
                        .arg(formatCompactAddress(entry.dispatchAddress));
                }
                else if (outsideOwnImage)
                {
                    ++evidence.majorFunctionExternalCount;
                    detailLines << driverText(
                        "driver.evidence.detail.major_function_external",
                        QStringLiteral("外跳: %1 dispatch=%2 module=%3 moduleBase=%4 location=%5"))
                        .arg(driverMajorFunctionName(entry.majorFunction))
                        .arg(formatCompactAddress(entry.dispatchAddress))
                        .arg(QString::fromStdWString(entry.moduleName))
                        .arg(formatCompactAddress(entry.moduleBase))
                        .arg(driverDispatchLocationText(entry.flags));
                }
            }
            if (evidence.majorFunctionExternalCount == 0U &&
                evidence.majorFunctionIntentionalBlindCount == 0U)
            {
                detailLines << driverText(
                    "driver.evidence.detail.major_function_clean",
                    QStringLiteral("未发现 MajorFunction 外跳。")) << QString();
            }
            else
            {
                detailLines << QString();
            }
        }
        evidence.hasMajorFunctionExternalJump = evidence.majorFunctionExternalCount != 0U;
        const std::uint32_t communicationConflictCount =
            evidenceCommunicationMaskCount(evidence.communicationConflictMask);
        if (evidence.communicationConflict)
        {
            evidence.majorFunctionStatusText = driverText(
                "driver.evidence.status.communication_conflict",
                QStringLiteral("主动致盲 %1/5 · 冲突 %2"))
                .arg(evidence.majorFunctionIntentionalBlindCount)
                .arg(communicationConflictCount);
        }
        else if (evidence.majorFunctionIntentionalBlindCount != 0U &&
            evidence.hasMajorFunctionExternalJump)
        {
            evidence.majorFunctionStatusText = driverText(
                "driver.evidence.status.communication_and_external",
                QStringLiteral("主动致盲 %1/5 · 未知外跳 %2"))
                .arg(evidence.majorFunctionIntentionalBlindCount)
                .arg(evidence.majorFunctionExternalCount);
        }
        else if (evidence.majorFunctionIntentionalBlindCount != 0U)
        {
            evidence.majorFunctionStatusText = driverText(
                "driver.evidence.status.communication_active",
                QStringLiteral("主动致盲 %1/5"))
                .arg(evidence.majorFunctionIntentionalBlindCount);
        }
        else
        {
            evidence.majorFunctionStatusText = evidence.hasMajorFunctionExternalJump
                ? driverText("driver.evidence.status.external_count", QStringLiteral("外跳 %1"))
                    .arg(evidence.majorFunctionExternalCount)
                : driverText("driver.evidence.status.no_external", QStringLiteral("未见外跳"));
        }

        detailLines << QStringLiteral("[IAT/EAT]");
        if (!iatEatResult.io.ok)
        {
            evidence.hasScanError = true;
            detailLines << driverText("driver.evidence.detail.scan_failed", QStringLiteral("扫描失败: %1"))
                .arg(describeDriverCollection(iatEatResult.io));
        }
        else
        {
            for (const ksword::ark::KernelIatEatHookEntry& entry : iatEatResult.entries)
            {
                const bool sameModule = entry.moduleBase == moduleRecord.baseAddress ||
                    evidenceModuleNameMatches(QString::fromStdWString(entry.moduleName), moduleRecord.moduleName);
                if (!sameModule || entry.status != KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS)
                {
                    continue;
                }
                ++evidence.iatEatSuspiciousCount;
                detailLines << driverText(
                    "driver.evidence.detail.iat_eat_suspicious",
                    QStringLiteral("可疑: %1 module=%2 import=%3 func=%4 thunk=%5 current=%6 expected=%7 targetModule=%8 status=%9"))
                    .arg(evidenceIatEatClassText(entry.hookClass))
                    .arg(QString::fromStdWString(entry.moduleName))
                    .arg(QString::fromStdWString(entry.importModuleName))
                    .arg(QString::fromLocal8Bit(entry.functionName.data(), static_cast<int>(entry.functionName.size())))
                    .arg(formatCompactAddress(entry.thunkAddress))
                    .arg(formatCompactAddress(entry.currentTarget))
                    .arg(formatCompactAddress(entry.expectedTarget))
                    .arg(QString::fromStdWString(entry.targetModuleName))
                    .arg(evidenceHookStatusText(entry.status));
            }
            if (evidence.iatEatSuspiciousCount == 0U)
            {
                detailLines << driverText(
                    "driver.evidence.detail.iat_eat_clean",
                    QStringLiteral("未发现该模块 IAT/EAT 可疑项。")) << QString();
            }
            else
            {
                detailLines << QString();
            }
        }
        evidence.hasIatEatSuspicious = evidence.iatEatSuspiciousCount != 0U;
        evidence.iatEatStatusText = evidence.hasIatEatSuspicious
            ? driverText("driver.evidence.status.suspicious_count", QStringLiteral("可疑 %1"))
                .arg(evidence.iatEatSuspiciousCount)
            : (iatEatResult.io.ok
                ? driverText("driver.evidence.status.no_suspicious", QStringLiteral("未见可疑"))
                : driverText("driver.evidence.status.scan_failed", QStringLiteral("扫描失败")));

        detailLines << QStringLiteral("[Inline Hook]");
        if (!inlineResult.io.ok)
        {
            evidence.hasScanError = true;
            detailLines << driverText("driver.evidence.detail.scan_failed", QStringLiteral("扫描失败: %1"))
                .arg(describeDriverCollection(inlineResult.io));
        }
        else
        {
            for (const ksword::ark::KernelInlineHookEntry& entry : inlineResult.entries)
            {
                const bool sameModule = entry.moduleBase == moduleRecord.baseAddress ||
                    evidenceModuleNameMatches(QString::fromStdWString(entry.moduleName), moduleRecord.moduleName);
                if (!sameModule || entry.status != KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS)
                {
                    continue;
                }
                ++evidence.inlineHookSuspiciousCount;
                detailLines << driverText(
                    "driver.evidence.detail.inline_suspicious",
                    QStringLiteral("可疑: module=%1 function=%2 address=%3 type=%4 target=%5 targetModule=%6 status=%7"))
                    .arg(QString::fromStdWString(entry.moduleName))
                    .arg(QString::fromLocal8Bit(entry.functionName.data(), static_cast<int>(entry.functionName.size())))
                    .arg(formatCompactAddress(entry.functionAddress))
                    .arg(evidenceInlineHookTypeText(entry.hookType))
                    .arg(formatCompactAddress(entry.targetAddress))
                    .arg(QString::fromStdWString(entry.targetModuleName))
                    .arg(evidenceHookStatusText(entry.status));
            }
            if (evidence.inlineHookSuspiciousCount == 0U)
            {
                detailLines << driverText(
                    "driver.evidence.detail.inline_clean",
                    QStringLiteral("未发现该模块 Inline Hook 可疑项。")) << QString();
            }
            else
            {
                detailLines << QString();
            }
        }
        evidence.hasInlineHookSuspicious = evidence.inlineHookSuspiciousCount != 0U;
        evidence.inlineHookStatusText = evidence.hasInlineHookSuspicious
            ? driverText("driver.evidence.status.suspicious_count", QStringLiteral("可疑 %1"))
                .arg(evidence.inlineHookSuspiciousCount)
            : (inlineResult.io.ok
                ? driverText("driver.evidence.status.no_suspicious", QStringLiteral("未见可疑"))
                : driverText("driver.evidence.status.scan_failed", QStringLiteral("扫描失败")));

        detailLines << QStringLiteral("[Callback]");
        if (!callbackResult.io.ok)
        {
            evidence.hasScanError = true;
            detailLines << driverText("driver.evidence.detail.enumeration_failed", QStringLiteral("枚举失败: %1"))
                .arg(describeDriverCollection(callbackResult.io));
        }
        else
        {
            for (const ksword::ark::CallbackEnumEntry& entry : callbackResult.entries)
            {
                const bool sameModule = entry.moduleBase == moduleRecord.baseAddress ||
                    evidenceAddressLooksInsideModule(entry.callbackAddress, moduleRecord.baseAddress, entry.moduleSize) ||
                    evidenceModuleNameMatches(QString::fromStdWString(entry.modulePath), moduleRecord.moduleName) ||
                    QString::fromStdWString(entry.modulePath).contains(moduleRecord.moduleName, Qt::CaseInsensitive);
                if (!sameModule)
                {
                    continue;
                }
                ++evidence.callbackReferenceCount;
                detailLines << driverText(
                    "driver.evidence.detail.callback_reference",
                    QStringLiteral("引用: class=%1 status=%2 callback=%3 context=%4 registration=%5 moduleBase=%6 modulePath=%7 name=%8 altitude=%9 detail=%10"))
                    .arg(evidenceCallbackClassText(entry.callbackClass))
                    .arg(evidenceCallbackStatusText(entry.status, entry.lastStatus))
                    .arg(formatCompactAddress(entry.callbackAddress))
                    .arg(formatCompactAddress(entry.contextAddress))
                    .arg(formatCompactAddress(entry.registrationAddress))
                    .arg(formatCompactAddress(entry.moduleBase))
                    .arg(QString::fromStdWString(entry.modulePath))
                    .arg(QString::fromStdWString(entry.name))
                    .arg(QString::fromStdWString(entry.altitude))
                    .arg(QString::fromStdWString(entry.detail));
            }
            if (evidence.callbackReferenceCount == 0U)
            {
                detailLines << driverText(
                    "driver.evidence.detail.callback_clean",
                    QStringLiteral("未发现 Callback 引用该模块。")) << QString();
            }
            else
            {
                detailLines << QString();
            }
        }
        evidence.hasCallbackReference = evidence.callbackReferenceCount != 0U;
        evidence.callbackStatusText = evidence.hasCallbackReference
            ? driverText("driver.evidence.status.reference_count", QStringLiteral("引用 %1"))
                .arg(evidence.callbackReferenceCount)
            : (callbackResult.io.ok
                ? driverText("driver.evidence.status.no_reference", QStringLiteral("未见引用"))
                : driverText("driver.evidence.status.enumeration_failed", QStringLiteral("枚举失败")));

        detailLines << driverText("driver.evidence.detail.global_summary", QStringLiteral("[全局扫描摘要]"));
        evidenceAppendIoSummary(detailLines, QStringLiteral("Inline Hook"), inlineResult.io);
        detailLines << driverText(
            "driver.evidence.detail.inline_summary",
            QStringLiteral("Inline returned=%1 total=%2 modules=%3 last=%4"))
            .arg(inlineResult.entries.size())
            .arg(inlineResult.totalCount)
            .arg(inlineResult.moduleCount)
            .arg(formatNtStatusText(inlineResult.lastStatus));
        evidenceAppendIoSummary(detailLines, QStringLiteral("IAT/EAT"), iatEatResult.io);
        detailLines << driverText(
            "driver.evidence.detail.iat_eat_summary",
            QStringLiteral("IAT/EAT returned=%1 total=%2 modules=%3 last=%4"))
            .arg(iatEatResult.entries.size())
            .arg(iatEatResult.totalCount)
            .arg(iatEatResult.moduleCount)
            .arg(formatNtStatusText(iatEatResult.lastStatus));
        evidenceAppendIoSummary(detailLines, QStringLiteral("Callback"), callbackResult.io);
        detailLines << driverText(
            "driver.evidence.detail.callback_summary",
            QStringLiteral("Callback returned=%1 total=%2 last=%3"))
            .arg(callbackResult.entries.size())
            .arg(callbackResult.totalCount)
            .arg(formatNtStatusText(callbackResult.lastStatus));

        evidence.detailText = detailLines.join('\n');
        evidenceRecords.push_back(std::move(evidence));
    }

    return evidenceRecords;
}

void DriverDock::refreshLoadedModuleEvidenceAsync()
{
    // 输入：当前已加载模块缓存；处理：后台聚合 R0 证据并回投 UI；返回：无。
    if (m_moduleEvidenceQuerying)
    {
        return;
    }
    if (m_loadedModuleCache.empty())
    {
        // 手动点击“证据刷新”但当前没有模块快照时，只提示用户先刷新模块：
        // - 输入：空 m_loadedModuleCache；
        // - 处理：不在这里反向调用 refreshLoadedKernelModuleRecords；
        // - 返回：无；避免空列表环境下模块刷新和证据刷新互相递归。
        if (m_moduleEvidenceStatusLabel != nullptr)
        {
            m_moduleEvidenceStatusLabel->setText(driverText(
                "driver.evidence.status.no_modules",
                QStringLiteral("证据：没有可聚合的模块，请先刷新已加载模块。")));
        }
        return;
    }

    m_moduleEvidenceQuerying = true;
    const std::uint64_t ticketValue = ++m_moduleEvidenceQueryTicket;
    if (m_refreshModuleEvidenceButton != nullptr)
    {
        m_refreshModuleEvidenceButton->setEnabled(false);
    }
    if (m_moduleEvidenceStatusLabel != nullptr)
    {
        m_moduleEvidenceStatusLabel->setText(driverText(
            "driver.evidence.status.aggregating",
            QStringLiteral("证据：正在刷新...")));
    }

    const std::vector<LoadedKernelModuleRecord> moduleSnapshot = m_loadedModuleCache;
    QObject* const applicationContext = QCoreApplication::instance();
    if (applicationContext == nullptr)
    {
        m_moduleEvidenceQuerying = false;
        if (m_refreshModuleEvidenceButton != nullptr)
        {
            m_refreshModuleEvidenceButton->setEnabled(true);
        }
        return;
    }

    QPointer<DriverDock> guardThis(this);
    auto* evidenceTask = QRunnable::create(
        [applicationContext, guardThis, ticketValue, moduleSnapshot]()
        {
            auto resultRecords = DriverDock::collectEvidenceForLoadedModules(moduleSnapshot);

            // 应用对象是稳定投递 context；QPointer 只在 GUI lambda 内检查并解引用。
            QMetaObject::invokeMethod(
                applicationContext,
                [guardThis, ticketValue, resultRecords = std::move(resultRecords)]() mutable
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }

                    const auto deferredRecords =
                        std::make_shared<std::vector<LoadedModuleEvidenceRecord>>(
                            std::move(resultRecords));
                    const auto commitEvidence = [guardThis, ticketValue, deferredRecords]()
                    {
                        if (guardThis == nullptr ||
                            guardThis->m_moduleEvidenceQueryTicket != ticketValue)
                        {
                            return;
                        }

                        guardThis->m_moduleEvidenceQuerying = false;
                        if (guardThis->m_refreshModuleEvidenceButton != nullptr)
                        {
                            guardThis->m_refreshModuleEvidenceButton->setEnabled(true);
                        }

                        guardThis->m_loadedModuleEvidenceCache = std::move(*deferredRecords);
                        // 签名状态本身也是搜索字段，因此后台完成后必须重新应用共享过滤器。
                        guardThis->rebuildLoadedModuleTable();
                        guardThis->updateLoadedModuleEvidenceStatusText();
                    };

                    if (guardThis == nullptr ||
                        guardThis->m_moduleEvidenceQueryTicket != ticketValue)
                    {
                        return;
                    }
                    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                        guardThis.data(),
                        QStringLiteral("driver-loaded-module-evidence-apply"),
                        { guardThis->m_moduleTable },
                        commitEvidence))
                    {
                        return;
                    }
                    commitEvidence();
                },
                Qt::QueuedConnection);
        });
    evidenceTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(evidenceTask);
}

void DriverDock::updateLoadedModuleEvidenceStatusText()
{
    if (m_moduleEvidenceStatusLabel == nullptr)
    {
        return;
    }
    if (m_moduleEvidenceQuerying)
    {
        m_moduleEvidenceStatusLabel->setText(driverText(
            "driver.evidence.status.aggregating",
            QStringLiteral("证据：正在刷新...")));
        return;
    }
    if (m_loadedModuleEvidenceCache.empty())
    {
        m_moduleEvidenceStatusLabel->setText(driverText(
            "driver.evidence.status.no_modules_short",
            QStringLiteral("证据：没有可聚合的模块。")));
        return;
    }

    const bool hasCompletedEvidence = std::any_of(
        m_loadedModuleEvidenceCache.cbegin(),
        m_loadedModuleEvidenceCache.cend(),
        [](const LoadedModuleEvidenceRecord& evidence)
        {
            return evidence.queryAttempted;
        });
    if (!hasCompletedEvidence)
    {
        m_moduleEvidenceStatusLabel->setText(driverText(
            "driver.evidence.status.modules_refreshed",
            QStringLiteral("证据：模块列表已刷新。")));
        return;
    }

    std::size_t suspiciousCount = 0U;
    std::size_t callbackCount = 0U;
    std::size_t errorCount = 0U;
    std::size_t invalidSignatureCount = 0U;
    for (const LoadedModuleEvidenceRecord& evidence :
        m_loadedModuleEvidenceCache)
    {
        if (evidence.hasMajorFunctionExternalJump ||
            evidence.hasIatEatSuspicious ||
            evidence.hasInlineHookSuspicious ||
            evidence.communicationConflict)
        {
            ++suspiciousCount;
        }
        if (evidence.hasCallbackReference)
        {
            ++callbackCount;
        }
        if (evidence.hasScanError)
        {
            ++errorCount;
        }
        if (moduleSignatureCheckAttempted(evidence) &&
            !moduleSignatureTrusted(evidence))
        {
            ++invalidSignatureCount;
        }
    }

    m_moduleEvidenceStatusLabel->setText(
        driverText(
            "driver.evidence.status.completed",
            QStringLiteral(
                "证据：已聚合 %1 个模块，可疑=%2，Callback引用=%3，错误=%4，签名无效=%5"))
        .arg(m_loadedModuleEvidenceCache.size())
        .arg(suspiciousCount)
        .arg(callbackCount)
        .arg(errorCount)
        .arg(invalidSignatureCount));
}

void DriverDock::rebuildLoadedModuleEvidenceViews()
{
    // 输入：当前模块表和证据缓存；处理：逐行回填证据列颜色/文本；返回：无。
    if (m_moduleTable == nullptr)
    {
        return;
    }

    for (int rowIndex = 0; rowIndex < m_moduleTable->rowCount(); ++rowIndex)
    {
        QTableWidgetItem* moduleItem = m_moduleTable->item(rowIndex, 0);
        if (moduleItem == nullptr)
        {
            continue;
        }

        const std::size_t sourceIndex = static_cast<std::size_t>(
            moduleItem->data(ModuleRecordIndexRole).toULongLong());
        if (sourceIndex >= m_loadedModuleEvidenceCache.size())
        {
            continue;
        }

        const LoadedModuleEvidenceRecord& evidence = m_loadedModuleEvidenceCache[sourceIndex];
        // invalidSignature 用途：只有后台确实完成校验且信任链失败时才整行标红。
        const bool invalidSignature =
            moduleSignatureCheckAttempted(evidence) &&
            !moduleSignatureTrusted(evidence);
        QColor invalidSignatureBackgroundColor = KswordTheme::ErrorColor();
        invalidSignatureBackgroundColor.setAlpha(48);
        for (int columnIndex = 0;
            columnIndex < m_moduleTable->columnCount();
            ++columnIndex)
        {
            QTableWidgetItem* rowItem = m_moduleTable->item(rowIndex, columnIndex);
            if (rowItem != nullptr)
            {
                rowItem->setBackground(
                    invalidSignature
                    ? QBrush(invalidSignatureBackgroundColor)
                    : QBrush());
            }
        }

        QTableWidgetItem* signatureItem =
            m_moduleTable->item(rowIndex, ModuleSignatureColumn);
        const QString signatureStatusText =
            moduleSignatureStatusText(evidence);
        const QString signatureDetailText =
            moduleSignatureDetailText(evidence);
        if (signatureItem == nullptr)
        {
            signatureItem = createReadOnlyItem(signatureStatusText);
            m_moduleTable->setItem(rowIndex, ModuleSignatureColumn, signatureItem);
        }
        else
        {
            signatureItem->setText(signatureStatusText);
        }
        const QColor signatureColor = !moduleSignatureCheckAttempted(evidence)
            ? KswordTheme::TextSecondaryColor()
            : (moduleSignatureTrusted(evidence)
                ? KswordTheme::SuccessColor()
                : KswordTheme::ErrorColor());
        signatureItem->setForeground(QBrush(signatureColor));
        signatureItem->setToolTip(signatureDetailText.left(4000));

        const QString pendingText = driverText(
            "driver.evidence.pending",
            QStringLiteral("待扫描"));
        const QString driverObjectStatusText = !evidence.queryAttempted
            ? pendingText
            : (evidence.driverObjectResolved
                ? driverText(
                    "driver.evidence.status.resolved",
                    QStringLiteral("已解析"))
                : driverText(
                    "driver.evidence.status.unresolved",
                    QStringLiteral("未解析")));
        const QString driverStartStatusText = !evidence.queryAttempted
            ? pendingText
            : (!evidence.driverStartKnown
                ? driverText(
                    "driver.evidence.status.unknown",
                    QStringLiteral("未知"))
                : (evidence.driverStartMatchesBase
                    ? driverText(
                        "driver.evidence.status.match",
                        QStringLiteral("匹配"))
                    : driverText(
                        "driver.evidence.status.mismatch",
                        QStringLiteral("不匹配"))));

        QString majorFunctionStatusText = pendingText;
        if (evidence.queryAttempted)
        {
            const std::uint32_t communicationConflictCount =
                evidenceCommunicationMaskCount(
                    evidence.communicationConflictMask);
            if (evidence.communicationConflict)
            {
                majorFunctionStatusText = driverText(
                    "driver.evidence.status.communication_conflict",
                    QStringLiteral("主动致盲 %1/5 · 冲突 %2"))
                    .arg(evidence.majorFunctionIntentionalBlindCount)
                    .arg(communicationConflictCount);
            }
            else if (evidence.majorFunctionIntentionalBlindCount != 0U &&
                evidence.hasMajorFunctionExternalJump)
            {
                majorFunctionStatusText = driverText(
                    "driver.evidence.status.communication_and_external",
                    QStringLiteral("主动致盲 %1/5 · 未知外跳 %2"))
                    .arg(evidence.majorFunctionIntentionalBlindCount)
                    .arg(evidence.majorFunctionExternalCount);
            }
            else if (evidence.majorFunctionIntentionalBlindCount != 0U)
            {
                majorFunctionStatusText = driverText(
                    "driver.evidence.status.communication_active",
                    QStringLiteral("主动致盲 %1/5"))
                    .arg(evidence.majorFunctionIntentionalBlindCount);
            }
            else
            {
                majorFunctionStatusText =
                    evidence.hasMajorFunctionExternalJump
                    ? driverText(
                        "driver.evidence.status.external_count",
                        QStringLiteral("外跳 %1"))
                        .arg(evidence.majorFunctionExternalCount)
                    : driverText(
                        "driver.evidence.status.no_external",
                        QStringLiteral("未见外跳"));
            }
        }

        const QString iatEatStatusText =
            evidence.queryAttempted && evidence.hasIatEatSuspicious
            ? driverText(
                "driver.evidence.status.suspicious_count",
                QStringLiteral("可疑 %1"))
                .arg(evidence.iatEatSuspiciousCount)
            : localizedModuleEvidenceText(evidence.iatEatStatusText);
        const QString inlineHookStatusText =
            evidence.queryAttempted && evidence.hasInlineHookSuspicious
            ? driverText(
                "driver.evidence.status.suspicious_count",
                QStringLiteral("可疑 %1"))
                .arg(evidence.inlineHookSuspiciousCount)
            : localizedModuleEvidenceText(evidence.inlineHookStatusText);
        const QString callbackStatusText =
            evidence.queryAttempted && evidence.hasCallbackReference
            ? driverText(
                "driver.evidence.status.reference_count",
                QStringLiteral("引用 %1"))
                .arg(evidence.callbackReferenceCount)
            : localizedModuleEvidenceText(evidence.callbackStatusText);
        const QStringList columnTexts = {
            driverObjectStatusText,
            driverStartStatusText,
            majorFunctionStatusText,
            iatEatStatusText,
            inlineHookStatusText,
            callbackStatusText
        };
        const QColor foregroundColor = moduleEvidenceStatusColor(evidence);
        for (int columnOffset = 0; columnOffset < columnTexts.size(); ++columnOffset)
        {
            const int columnIndex = ModuleEvidenceFirstColumn + columnOffset;
            QTableWidgetItem* cellItem = m_moduleTable->item(rowIndex, columnIndex);
            if (cellItem == nullptr)
            {
                cellItem = createReadOnlyItem(columnTexts[columnOffset]);
                m_moduleTable->setItem(rowIndex, columnIndex, cellItem);
            }
            else
            {
                cellItem->setText(columnTexts[columnOffset]);
            }
            cellItem->setForeground(QBrush(foregroundColor));
            // 完整证据已经显示在表格下方的详情区；证据列不再重复挂载
            // 最长 4000 字符的悬停文本，避免 tooltip 遮挡整个主窗口。
            cellItem->setToolTip(QString());
        }
    }

    showSelectedModuleEvidenceDetail();
}

void DriverDock::showSelectedModuleEvidenceDetail()
{
    // 输入：当前模块表选择；处理：读取缓存并显示详情；返回：无。
    if (m_moduleEvidenceDetailEditor == nullptr)
    {
        return;
    }
    if (m_moduleTable == nullptr || m_moduleTable->selectionModel() == nullptr)
    {
        m_moduleEvidenceDetailEditor->setLocalizedText(
            driverText("driver.evidence.detail.table_unavailable", QStringLiteral("模块表不可用。")));
        return;
    }

    const QModelIndexList selectedRows = m_moduleTable->selectionModel()->selectedRows(0);
    if (selectedRows.isEmpty())
    {
        m_moduleEvidenceDetailEditor->setLocalizedText(driverText(
            "driver.evidence.detail.select_module",
            QStringLiteral("请选择一条已加载模块查看聚合证据。")));
        return;
    }

    const int rowIndex = selectedRows.front().row();
    QTableWidgetItem* moduleItem = m_moduleTable->item(rowIndex, 0);
    if (moduleItem == nullptr)
    {
        m_moduleEvidenceDetailEditor->setLocalizedText(
            driverText("driver.evidence.detail.module_name_missing", QStringLiteral("当前行没有模块名。")));
        return;
    }

    const std::size_t sourceIndex = static_cast<std::size_t>(
        moduleItem->data(ModuleRecordIndexRole).toULongLong());
    if (sourceIndex >= m_loadedModuleEvidenceCache.size())
    {
        m_moduleEvidenceDetailEditor->setLocalizedText(
            driverText("driver.evidence.detail.not_generated", QStringLiteral("模块 %1 尚未生成证据详情。"))
            .arg(moduleItem->text()));
        return;
    }

    const LoadedModuleEvidenceRecord& evidence =
        m_loadedModuleEvidenceCache[sourceIndex];
    const LoadedKernelModuleRecord* moduleRecord =
        sourceIndex < m_loadedModuleCache.size()
        ? &m_loadedModuleCache[sourceIndex]
        : nullptr;
    const QString signatureSummary = driverText(
        "driver.evidence.detail.signature",
        QStringLiteral("数字签名: %1"))
        .arg(moduleSignatureStatusText(evidence));
    QString evidenceBody;
    if (!evidence.queryAttempted)
    {
        evidenceBody = driverText(
            "driver.evidence.pending.detail",
            QStringLiteral(
                "模块 %1 尚未执行证据聚合。\n"
                "点击工具栏证据刷新按钮后，后台线程会只读查询 DriverObject / Hook / Callback。"))
            .arg(evidence.moduleName);
    }
    else
    {
        evidenceBody = localizedModuleEvidenceText(evidence.detailText);
    }

    QStringList localizedDetailLines;
    localizedDetailLines
        << driverText(
            "driver.evidence.detail.title",
            QStringLiteral("模块证据聚合"))
        << driverText(
            "driver.evidence.detail.module",
            QStringLiteral("模块: %1"))
            .arg(evidence.moduleName);
    if (moduleRecord != nullptr)
    {
        localizedDetailLines
            << driverText(
                "driver.evidence.detail.base",
                QStringLiteral("基址: %1"))
                .arg(formatCompactAddress(moduleRecord->baseAddress))
            << driverText(
                "driver.evidence.detail.image_path",
                QStringLiteral("映像路径: %1"))
                .arg(moduleRecord->imagePath);
    }
    localizedDetailLines
        << signatureSummary
        << moduleSignatureDetailText(evidence)
        << driverText(
            "driver.evidence.detail.read_only_note",
            QStringLiteral("说明: 本结果仅聚合证据，不执行卸载、移除或修复。"))
        << QString()
        << evidenceBody;
    m_moduleEvidenceDetailEditor->setRawText(
        localizedDetailLines.join(QLatin1Char('\n')));
}
