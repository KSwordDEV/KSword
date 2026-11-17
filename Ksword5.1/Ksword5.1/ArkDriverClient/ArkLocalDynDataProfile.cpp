#include "ArkLocalDynDataProfile.h"
#include "../ksword/profile/ProfileJsonLoader.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QStringList>
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <unordered_map>

namespace
{
    using ksword::ark::LocalPdbProfile;
    thread_local const ksword::ark::DynDataProfileText* profileTexts = nullptr;
    QString kernelText(const char* key, const QString& source)
    {
        return profileTexts && *profileTexts ? (*profileTexts)(key, source) : source;
    }
    // fieldIdForProfileName：
    // - 输入 fieldName：JSON profile 中的字段名；
    // - 处理：映射到 shared/driver/KswordArkDynDataIoctl.h 中的字段 ID；
    // - 返回：命中返回 true，否则 false，由调用方记录未知字段诊断。
    bool fieldIdForProfileName(const QString& fieldName, std::uint32_t& fieldIdOut)
    {
        static const std::unordered_map<std::string, std::uint32_t> kFieldIds = {
            { "EpObjectTable", KSW_DYN_FIELD_ID_EP_OBJECT_TABLE },
            { "EpSectionObject", KSW_DYN_FIELD_ID_EP_SECTION_OBJECT },
            { "EpUniqueProcessId", KSW_DYN_FIELD_ID_EP_UNIQUE_PROCESS_ID },
            { "_EPROCESS.UniqueProcessId", KSW_DYN_FIELD_ID_EP_UNIQUE_PROCESS_ID },
            { "EpActiveProcessLinks", KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS },
            { "_EPROCESS.ActiveProcessLinks", KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS },
            { "EpThreadListHead", KSW_DYN_FIELD_ID_EP_THREAD_LIST_HEAD },
            { "_EPROCESS.ThreadListHead", KSW_DYN_FIELD_ID_EP_THREAD_LIST_HEAD },
            { "EpImageFileName", KSW_DYN_FIELD_ID_EP_IMAGE_FILE_NAME },
            { "_EPROCESS.ImageFileName", KSW_DYN_FIELD_ID_EP_IMAGE_FILE_NAME },
            { "EpToken", KSW_DYN_FIELD_ID_EP_TOKEN },
            { "_EPROCESS.Token", KSW_DYN_FIELD_ID_EP_TOKEN },
            { "EpFlags", KSW_DYN_FIELD_ID_EP_FLAGS },
            { "_EPROCESS.Flags", KSW_DYN_FIELD_ID_EP_FLAGS },
            { "EpFlags2", KSW_DYN_FIELD_ID_EP_FLAGS2 },
            { "_EPROCESS.Flags2", KSW_DYN_FIELD_ID_EP_FLAGS2 },
            { "EpRundownProtect", KSW_DYN_FIELD_ID_EP_RUNDOWN_PROTECT },
            { "_EPROCESS.RundownProtect", KSW_DYN_FIELD_ID_EP_RUNDOWN_PROTECT },
            { "EpProcessLock", KSW_DYN_FIELD_ID_EP_PROCESS_LOCK },
            { "_EPROCESS.ProcessLock", KSW_DYN_FIELD_ID_EP_PROCESS_LOCK },
            { "EpCreateTime", KSW_DYN_FIELD_ID_EP_CREATE_TIME },
            { "_EPROCESS.CreateTime", KSW_DYN_FIELD_ID_EP_CREATE_TIME },
            { "EpExitTime", KSW_DYN_FIELD_ID_EP_EXIT_TIME },
            { "_EPROCESS.ExitTime", KSW_DYN_FIELD_ID_EP_EXIT_TIME },
            { "EpExitStatus", KSW_DYN_FIELD_ID_EP_EXIT_STATUS },
            { "_EPROCESS.ExitStatus", KSW_DYN_FIELD_ID_EP_EXIT_STATUS },
            { "EpPeb", KSW_DYN_FIELD_ID_EP_PEB },
            { "_EPROCESS.Peb", KSW_DYN_FIELD_ID_EP_PEB },
            { "EpSession", KSW_DYN_FIELD_ID_EP_SESSION },
            { "_EPROCESS.Session", KSW_DYN_FIELD_ID_EP_SESSION },
            { "EpWin32Process", KSW_DYN_FIELD_ID_EP_WIN32_PROCESS },
            { "_EPROCESS.Win32Process", KSW_DYN_FIELD_ID_EP_WIN32_PROCESS },
            { "EpWow64Process", KSW_DYN_FIELD_ID_EP_WOW64_PROCESS },
            { "EpWoW64Process", KSW_DYN_FIELD_ID_EP_WOW64_PROCESS },
            { "_EPROCESS.WoW64Process", KSW_DYN_FIELD_ID_EP_WOW64_PROCESS },
            { "EpInheritedFromUniqueProcessId", KSW_DYN_FIELD_ID_EP_INHERITED_FROM_UNIQUE_PROCESS_ID },
            { "_EPROCESS.InheritedFromUniqueProcessId", KSW_DYN_FIELD_ID_EP_INHERITED_FROM_UNIQUE_PROCESS_ID },
            { "EpSeAuditProcessCreationInfo", KSW_DYN_FIELD_ID_EP_SE_AUDIT_PROCESS_CREATION_INFO },
            { "_EPROCESS.SeAuditProcessCreationInfo", KSW_DYN_FIELD_ID_EP_SE_AUDIT_PROCESS_CREATION_INFO },
            { "EpJob", KSW_DYN_FIELD_ID_EP_JOB },
            { "_EPROCESS.Job", KSW_DYN_FIELD_ID_EP_JOB },
            { "EpDeviceMap", KSW_DYN_FIELD_ID_EP_DEVICE_MAP },
            { "_EPROCESS.DeviceMap", KSW_DYN_FIELD_ID_EP_DEVICE_MAP },
            { "EpDebugPort", KSW_DYN_FIELD_ID_EP_DEBUG_PORT },
            { "_EPROCESS.DebugPort", KSW_DYN_FIELD_ID_EP_DEBUG_PORT },
            { "EpExceptionPortData", KSW_DYN_FIELD_ID_EP_EXCEPTION_PORT_DATA },
            { "_EPROCESS.ExceptionPortData", KSW_DYN_FIELD_ID_EP_EXCEPTION_PORT_DATA },
            { "EpSectionBaseAddress", KSW_DYN_FIELD_ID_EP_SECTION_BASE_ADDRESS },
            { "_EPROCESS.SectionBaseAddress", KSW_DYN_FIELD_ID_EP_SECTION_BASE_ADDRESS },
            { "EpImageFilePointer", KSW_DYN_FIELD_ID_EP_IMAGE_FILE_POINTER },
            { "_EPROCESS.ImageFilePointer", KSW_DYN_FIELD_ID_EP_IMAGE_FILE_POINTER },
            { "EpPriorityClass", KSW_DYN_FIELD_ID_EP_PRIORITY_CLASS },
            { "_EPROCESS.PriorityClass", KSW_DYN_FIELD_ID_EP_PRIORITY_CLASS },
            { "EpActiveThreads", KSW_DYN_FIELD_ID_EP_ACTIVE_THREADS },
            { "_EPROCESS.ActiveThreads", KSW_DYN_FIELD_ID_EP_ACTIVE_THREADS },
            { "EpVadRoot", KSW_DYN_FIELD_ID_EP_VAD_ROOT },
            { "_EPROCESS.VadRoot", KSW_DYN_FIELD_ID_EP_VAD_ROOT },
            { "EpVadHint", KSW_DYN_FIELD_ID_EP_VAD_HINT },
            { "_EPROCESS.VadHint", KSW_DYN_FIELD_ID_EP_VAD_HINT },
            { "EpCloneRoot", KSW_DYN_FIELD_ID_EP_CLONE_ROOT },
            { "_EPROCESS.CloneRoot", KSW_DYN_FIELD_ID_EP_CLONE_ROOT },
            { "EpNumberOfPrivatePages", KSW_DYN_FIELD_ID_EP_NUMBER_OF_PRIVATE_PAGES },
            { "_EPROCESS.NumberOfPrivatePages", KSW_DYN_FIELD_ID_EP_NUMBER_OF_PRIVATE_PAGES },
            { "EpNumberOfLockedPages", KSW_DYN_FIELD_ID_EP_NUMBER_OF_LOCKED_PAGES },
            { "_EPROCESS.NumberOfLockedPages", KSW_DYN_FIELD_ID_EP_NUMBER_OF_LOCKED_PAGES },
            { "EpCommitCharge", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE },
            { "_EPROCESS.CommitCharge", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE },
            { "EpCommitChargePeak", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_PEAK },
            { "_EPROCESS.CommitChargePeak", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_PEAK },
            { "EpPeakVirtualSize", KSW_DYN_FIELD_ID_EP_PEAK_VIRTUAL_SIZE },
            { "_EPROCESS.PeakVirtualSize", KSW_DYN_FIELD_ID_EP_PEAK_VIRTUAL_SIZE },
            { "EpVirtualSize", KSW_DYN_FIELD_ID_EP_VIRTUAL_SIZE },
            { "_EPROCESS.VirtualSize", KSW_DYN_FIELD_ID_EP_VIRTUAL_SIZE },
            { "EpSessionProcessLinks", KSW_DYN_FIELD_ID_EP_SESSION_PROCESS_LINKS },
            { "_EPROCESS.SessionProcessLinks", KSW_DYN_FIELD_ID_EP_SESSION_PROCESS_LINKS },
            { "EpMitigationFlags", KSW_DYN_FIELD_ID_EP_MITIGATION_FLAGS },
            { "_EPROCESS.MitigationFlags", KSW_DYN_FIELD_ID_EP_MITIGATION_FLAGS },
            { "EpMitigationFlags2", KSW_DYN_FIELD_ID_EP_MITIGATION_FLAGS2 },
            { "_EPROCESS.MitigationFlags2", KSW_DYN_FIELD_ID_EP_MITIGATION_FLAGS2 },
            { "EpProcessQuotaUsage", KSW_DYN_FIELD_ID_EP_PROCESS_QUOTA_USAGE },
            { "_EPROCESS.ProcessQuotaUsage", KSW_DYN_FIELD_ID_EP_PROCESS_QUOTA_USAGE },
            { "EpProcessQuotaPeak", KSW_DYN_FIELD_ID_EP_PROCESS_QUOTA_PEAK },
            { "_EPROCESS.ProcessQuotaPeak", KSW_DYN_FIELD_ID_EP_PROCESS_QUOTA_PEAK },
            { "EpAddressCreationLock", KSW_DYN_FIELD_ID_EP_ADDRESS_CREATION_LOCK },
            { "_EPROCESS.AddressCreationLock", KSW_DYN_FIELD_ID_EP_ADDRESS_CREATION_LOCK },
            { "EpPageTableCommitmentLock", KSW_DYN_FIELD_ID_EP_PAGE_TABLE_COMMITMENT_LOCK },
            { "_EPROCESS.PageTableCommitmentLock", KSW_DYN_FIELD_ID_EP_PAGE_TABLE_COMMITMENT_LOCK },
            { "EpRotateInProgress", KSW_DYN_FIELD_ID_EP_ROTATE_IN_PROGRESS },
            { "_EPROCESS.RotateInProgress", KSW_DYN_FIELD_ID_EP_ROTATE_IN_PROGRESS },
            { "EpForkInProgress", KSW_DYN_FIELD_ID_EP_FORK_IN_PROGRESS },
            { "_EPROCESS.ForkInProgress", KSW_DYN_FIELD_ID_EP_FORK_IN_PROGRESS },
            { "EpCommitChargeJob", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_JOB },
            { "_EPROCESS.CommitChargeJob", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_JOB },
            { "EpCookie", KSW_DYN_FIELD_ID_EP_COOKIE },
            { "_EPROCESS.Cookie", KSW_DYN_FIELD_ID_EP_COOKIE },
            { "EpWorkingSetWatch", KSW_DYN_FIELD_ID_EP_WORKING_SET_WATCH },
            { "_EPROCESS.WorkingSetWatch", KSW_DYN_FIELD_ID_EP_WORKING_SET_WATCH },
            { "EpWin32WindowStation", KSW_DYN_FIELD_ID_EP_WIN32_WINDOW_STATION },
            { "_EPROCESS.Win32WindowStation", KSW_DYN_FIELD_ID_EP_WIN32_WINDOW_STATION },
            { "EpOwnerProcessId", KSW_DYN_FIELD_ID_EP_OWNER_PROCESS_ID },
            { "_EPROCESS.OwnerProcessId", KSW_DYN_FIELD_ID_EP_OWNER_PROCESS_ID },
            { "EpQuotaBlock", KSW_DYN_FIELD_ID_EP_QUOTA_BLOCK },
            { "_EPROCESS.QuotaBlock", KSW_DYN_FIELD_ID_EP_QUOTA_BLOCK },
            { "EpEtwDataSource", KSW_DYN_FIELD_ID_EP_ETW_DATA_SOURCE },
            { "_EPROCESS.EtwDataSource", KSW_DYN_FIELD_ID_EP_ETW_DATA_SOURCE },
            { "EpPageDirectoryPte", KSW_DYN_FIELD_ID_EP_PAGE_DIRECTORY_PTE },
            { "_EPROCESS.PageDirectoryPte", KSW_DYN_FIELD_ID_EP_PAGE_DIRECTORY_PTE },
            { "EpSecurityPort", KSW_DYN_FIELD_ID_EP_SECURITY_PORT },
            { "_EPROCESS.SecurityPort", KSW_DYN_FIELD_ID_EP_SECURITY_PORT },
            { "EpJobLinks", KSW_DYN_FIELD_ID_EP_JOB_LINKS },
            { "_EPROCESS.JobLinks", KSW_DYN_FIELD_ID_EP_JOB_LINKS },
            { "EpHighestUserAddress", KSW_DYN_FIELD_ID_EP_HIGHEST_USER_ADDRESS },
            { "_EPROCESS.HighestUserAddress", KSW_DYN_FIELD_ID_EP_HIGHEST_USER_ADDRESS },
            { "EpImagePathHash", KSW_DYN_FIELD_ID_EP_IMAGE_PATH_HASH },
            { "_EPROCESS.ImagePathHash", KSW_DYN_FIELD_ID_EP_IMAGE_PATH_HASH },
            { "EpDefaultHardErrorProcessing", KSW_DYN_FIELD_ID_EP_DEFAULT_HARD_ERROR_PROCESSING },
            { "_EPROCESS.DefaultHardErrorProcessing", KSW_DYN_FIELD_ID_EP_DEFAULT_HARD_ERROR_PROCESSING },
            { "EpLastThreadExitStatus", KSW_DYN_FIELD_ID_EP_LAST_THREAD_EXIT_STATUS },
            { "_EPROCESS.LastThreadExitStatus", KSW_DYN_FIELD_ID_EP_LAST_THREAD_EXIT_STATUS },
            { "EpPrefetchTrace", KSW_DYN_FIELD_ID_EP_PREFETCH_TRACE },
            { "_EPROCESS.PrefetchTrace", KSW_DYN_FIELD_ID_EP_PREFETCH_TRACE },
            { "EpLockedPagesList", KSW_DYN_FIELD_ID_EP_LOCKED_PAGES_LIST },
            { "_EPROCESS.LockedPagesList", KSW_DYN_FIELD_ID_EP_LOCKED_PAGES_LIST },
            { "EpReadOperationCount", KSW_DYN_FIELD_ID_EP_READ_OPERATION_COUNT },
            { "_EPROCESS.ReadOperationCount", KSW_DYN_FIELD_ID_EP_READ_OPERATION_COUNT },
            { "EpWriteOperationCount", KSW_DYN_FIELD_ID_EP_WRITE_OPERATION_COUNT },
            { "_EPROCESS.WriteOperationCount", KSW_DYN_FIELD_ID_EP_WRITE_OPERATION_COUNT },
            { "EpOtherOperationCount", KSW_DYN_FIELD_ID_EP_OTHER_OPERATION_COUNT },
            { "_EPROCESS.OtherOperationCount", KSW_DYN_FIELD_ID_EP_OTHER_OPERATION_COUNT },
            { "EpReadTransferCount", KSW_DYN_FIELD_ID_EP_READ_TRANSFER_COUNT },
            { "_EPROCESS.ReadTransferCount", KSW_DYN_FIELD_ID_EP_READ_TRANSFER_COUNT },
            { "EpWriteTransferCount", KSW_DYN_FIELD_ID_EP_WRITE_TRANSFER_COUNT },
            { "_EPROCESS.WriteTransferCount", KSW_DYN_FIELD_ID_EP_WRITE_TRANSFER_COUNT },
            { "EpOtherTransferCount", KSW_DYN_FIELD_ID_EP_OTHER_TRANSFER_COUNT },
            { "_EPROCESS.OtherTransferCount", KSW_DYN_FIELD_ID_EP_OTHER_TRANSFER_COUNT },
            { "EpCommitChargeLimit", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_LIMIT },
            { "_EPROCESS.CommitChargeLimit", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_LIMIT },
            { "EpVm", KSW_DYN_FIELD_ID_EP_VM },
            { "_EPROCESS.Vm", KSW_DYN_FIELD_ID_EP_VM },
            { "EpMmProcessLinks", KSW_DYN_FIELD_ID_EP_MM_PROCESS_LINKS },
            { "_EPROCESS.MmProcessLinks", KSW_DYN_FIELD_ID_EP_MM_PROCESS_LINKS },
            { "EpModifiedPageCount", KSW_DYN_FIELD_ID_EP_MODIFIED_PAGE_COUNT },
            { "_EPROCESS.ModifiedPageCount", KSW_DYN_FIELD_ID_EP_MODIFIED_PAGE_COUNT },
            { "EpVadCount", KSW_DYN_FIELD_ID_EP_VAD_COUNT },
            { "_EPROCESS.VadCount", KSW_DYN_FIELD_ID_EP_VAD_COUNT },
            { "EpVadPhysicalPages", KSW_DYN_FIELD_ID_EP_VAD_PHYSICAL_PAGES },
            { "_EPROCESS.VadPhysicalPages", KSW_DYN_FIELD_ID_EP_VAD_PHYSICAL_PAGES },
            { "EpVadPhysicalPagesLimit", KSW_DYN_FIELD_ID_EP_VAD_PHYSICAL_PAGES_LIMIT },
            { "_EPROCESS.VadPhysicalPagesLimit", KSW_DYN_FIELD_ID_EP_VAD_PHYSICAL_PAGES_LIMIT },
            { "EpAlpcContext", KSW_DYN_FIELD_ID_EP_ALPC_CONTEXT },
            { "_EPROCESS.AlpcContext", KSW_DYN_FIELD_ID_EP_ALPC_CONTEXT },
            { "EpTimerResolutionLink", KSW_DYN_FIELD_ID_EP_TIMER_RESOLUTION_LINK },
            { "_EPROCESS.TimerResolutionLink", KSW_DYN_FIELD_ID_EP_TIMER_RESOLUTION_LINK },
            { "EpTimerResolutionStackRecord", KSW_DYN_FIELD_ID_EP_TIMER_RESOLUTION_STACK_RECORD },
            { "_EPROCESS.TimerResolutionStackRecord", KSW_DYN_FIELD_ID_EP_TIMER_RESOLUTION_STACK_RECORD },
            { "EpRequestedTimerResolution", KSW_DYN_FIELD_ID_EP_REQUESTED_TIMER_RESOLUTION },
            { "_EPROCESS.RequestedTimerResolution", KSW_DYN_FIELD_ID_EP_REQUESTED_TIMER_RESOLUTION },
            { "EpSmallestTimerResolution", KSW_DYN_FIELD_ID_EP_SMALLEST_TIMER_RESOLUTION },
            { "_EPROCESS.SmallestTimerResolution", KSW_DYN_FIELD_ID_EP_SMALLEST_TIMER_RESOLUTION },
            { "EpInvertedFunctionTable", KSW_DYN_FIELD_ID_EP_INVERTED_FUNCTION_TABLE },
            { "_EPROCESS.InvertedFunctionTable", KSW_DYN_FIELD_ID_EP_INVERTED_FUNCTION_TABLE },
            { "EpInvertedFunctionTableLock", KSW_DYN_FIELD_ID_EP_INVERTED_FUNCTION_TABLE_LOCK },
            { "_EPROCESS.InvertedFunctionTableLock", KSW_DYN_FIELD_ID_EP_INVERTED_FUNCTION_TABLE_LOCK },
            { "EpActiveThreadsHighWatermark", KSW_DYN_FIELD_ID_EP_ACTIVE_THREADS_HIGH_WATERMARK },
            { "_EPROCESS.ActiveThreadsHighWatermark", KSW_DYN_FIELD_ID_EP_ACTIVE_THREADS_HIGH_WATERMARK },
            { "EpLargePrivateVadCount", KSW_DYN_FIELD_ID_EP_LARGE_PRIVATE_VAD_COUNT },
            { "_EPROCESS.LargePrivateVadCount", KSW_DYN_FIELD_ID_EP_LARGE_PRIVATE_VAD_COUNT },
            { "EpThreadListLock", KSW_DYN_FIELD_ID_EP_THREAD_LIST_LOCK },
            { "_EPROCESS.ThreadListLock", KSW_DYN_FIELD_ID_EP_THREAD_LIST_LOCK },
            { "EpWnfContext", KSW_DYN_FIELD_ID_EP_WNF_CONTEXT },
            { "_EPROCESS.WnfContext", KSW_DYN_FIELD_ID_EP_WNF_CONTEXT },
            { "EpFlags3", KSW_DYN_FIELD_ID_EP_FLAGS3 },
            { "_EPROCESS.Flags3", KSW_DYN_FIELD_ID_EP_FLAGS3 },
            { "EpDiskCounters", KSW_DYN_FIELD_ID_EP_DISK_COUNTERS },
            { "_EPROCESS.DiskCounters", KSW_DYN_FIELD_ID_EP_DISK_COUNTERS },
            { "TokTokenSource", KSW_DYN_FIELD_ID_TOK_TOKEN_SOURCE },
            { "_TOKEN.TokenSource", KSW_DYN_FIELD_ID_TOK_TOKEN_SOURCE },
            { "TokTokenId", KSW_DYN_FIELD_ID_TOK_TOKEN_ID },
            { "_TOKEN.TokenId", KSW_DYN_FIELD_ID_TOK_TOKEN_ID },
            { "TokAuthenticationId", KSW_DYN_FIELD_ID_TOK_AUTHENTICATION_ID },
            { "_TOKEN.AuthenticationId", KSW_DYN_FIELD_ID_TOK_AUTHENTICATION_ID },
            { "TokParentTokenId", KSW_DYN_FIELD_ID_TOK_PARENT_TOKEN_ID },
            { "_TOKEN.ParentTokenId", KSW_DYN_FIELD_ID_TOK_PARENT_TOKEN_ID },
            { "TokExpirationTime", KSW_DYN_FIELD_ID_TOK_EXPIRATION_TIME },
            { "_TOKEN.ExpirationTime", KSW_DYN_FIELD_ID_TOK_EXPIRATION_TIME },
            { "TokTokenLock", KSW_DYN_FIELD_ID_TOK_TOKEN_LOCK },
            { "_TOKEN.TokenLock", KSW_DYN_FIELD_ID_TOK_TOKEN_LOCK },
            { "TokModifiedId", KSW_DYN_FIELD_ID_TOK_MODIFIED_ID },
            { "_TOKEN.ModifiedId", KSW_DYN_FIELD_ID_TOK_MODIFIED_ID },
            { "TokPrivileges", KSW_DYN_FIELD_ID_TOK_PRIVILEGES },
            { "_TOKEN.Privileges", KSW_DYN_FIELD_ID_TOK_PRIVILEGES },
            { "TokAuditPolicy", KSW_DYN_FIELD_ID_TOK_AUDIT_POLICY },
            { "_TOKEN.AuditPolicy", KSW_DYN_FIELD_ID_TOK_AUDIT_POLICY },
            { "TokSessionId", KSW_DYN_FIELD_ID_TOK_SESSION_ID },
            { "_TOKEN.SessionId", KSW_DYN_FIELD_ID_TOK_SESSION_ID },
            { "TokUserAndGroupCount", KSW_DYN_FIELD_ID_TOK_USER_AND_GROUP_COUNT },
            { "_TOKEN.UserAndGroupCount", KSW_DYN_FIELD_ID_TOK_USER_AND_GROUP_COUNT },
            { "TokRestrictedSidCount", KSW_DYN_FIELD_ID_TOK_RESTRICTED_SID_COUNT },
            { "_TOKEN.RestrictedSidCount", KSW_DYN_FIELD_ID_TOK_RESTRICTED_SID_COUNT },
            { "TokVariableLength", KSW_DYN_FIELD_ID_TOK_VARIABLE_LENGTH },
            { "_TOKEN.VariableLength", KSW_DYN_FIELD_ID_TOK_VARIABLE_LENGTH },
            { "TokDynamicCharged", KSW_DYN_FIELD_ID_TOK_DYNAMIC_CHARGED },
            { "_TOKEN.DynamicCharged", KSW_DYN_FIELD_ID_TOK_DYNAMIC_CHARGED },
            { "TokDynamicAvailable", KSW_DYN_FIELD_ID_TOK_DYNAMIC_AVAILABLE },
            { "_TOKEN.DynamicAvailable", KSW_DYN_FIELD_ID_TOK_DYNAMIC_AVAILABLE },
            { "TokDefaultOwnerIndex", KSW_DYN_FIELD_ID_TOK_DEFAULT_OWNER_INDEX },
            { "_TOKEN.DefaultOwnerIndex", KSW_DYN_FIELD_ID_TOK_DEFAULT_OWNER_INDEX },
            { "TokUserAndGroups", KSW_DYN_FIELD_ID_TOK_USER_AND_GROUPS },
            { "_TOKEN.UserAndGroups", KSW_DYN_FIELD_ID_TOK_USER_AND_GROUPS },
            { "TokRestrictedSids", KSW_DYN_FIELD_ID_TOK_RESTRICTED_SIDS },
            { "_TOKEN.RestrictedSids", KSW_DYN_FIELD_ID_TOK_RESTRICTED_SIDS },
            { "TokPrimaryGroup", KSW_DYN_FIELD_ID_TOK_PRIMARY_GROUP },
            { "_TOKEN.PrimaryGroup", KSW_DYN_FIELD_ID_TOK_PRIMARY_GROUP },
            { "TokDynamicPart", KSW_DYN_FIELD_ID_TOK_DYNAMIC_PART },
            { "_TOKEN.DynamicPart", KSW_DYN_FIELD_ID_TOK_DYNAMIC_PART },
            { "TokDefaultDacl", KSW_DYN_FIELD_ID_TOK_DEFAULT_DACL },
            { "_TOKEN.DefaultDacl", KSW_DYN_FIELD_ID_TOK_DEFAULT_DACL },
            { "TokTokenType", KSW_DYN_FIELD_ID_TOK_TOKEN_TYPE },
            { "_TOKEN.TokenType", KSW_DYN_FIELD_ID_TOK_TOKEN_TYPE },
            { "TokImpersonationLevel", KSW_DYN_FIELD_ID_TOK_IMPERSONATION_LEVEL },
            { "_TOKEN.ImpersonationLevel", KSW_DYN_FIELD_ID_TOK_IMPERSONATION_LEVEL },
            { "TokTokenFlags", KSW_DYN_FIELD_ID_TOK_TOKEN_FLAGS },
            { "_TOKEN.TokenFlags", KSW_DYN_FIELD_ID_TOK_TOKEN_FLAGS },
            { "TokTokenInUse", KSW_DYN_FIELD_ID_TOK_TOKEN_IN_USE },
            { "_TOKEN.TokenInUse", KSW_DYN_FIELD_ID_TOK_TOKEN_IN_USE },
            { "TokIntegrityLevelIndex", KSW_DYN_FIELD_ID_TOK_INTEGRITY_LEVEL_INDEX },
            { "_TOKEN.IntegrityLevelIndex", KSW_DYN_FIELD_ID_TOK_INTEGRITY_LEVEL_INDEX },
            { "TokMandatoryPolicy", KSW_DYN_FIELD_ID_TOK_MANDATORY_POLICY },
            { "_TOKEN.MandatoryPolicy", KSW_DYN_FIELD_ID_TOK_MANDATORY_POLICY },
            { "TokLogonSession", KSW_DYN_FIELD_ID_TOK_LOGON_SESSION },
            { "_TOKEN.LogonSession", KSW_DYN_FIELD_ID_TOK_LOGON_SESSION },
            { "TokOriginatingLogonSession", KSW_DYN_FIELD_ID_TOK_ORIGINATING_LOGON_SESSION },
            { "_TOKEN.OriginatingLogonSession", KSW_DYN_FIELD_ID_TOK_ORIGINATING_LOGON_SESSION },
            { "TokSidHash", KSW_DYN_FIELD_ID_TOK_SID_HASH },
            { "_TOKEN.SidHash", KSW_DYN_FIELD_ID_TOK_SID_HASH },
            { "TokRestrictedSidHash", KSW_DYN_FIELD_ID_TOK_RESTRICTED_SID_HASH },
            { "_TOKEN.RestrictedSidHash", KSW_DYN_FIELD_ID_TOK_RESTRICTED_SID_HASH },
            { "TokPSecurityAttributes", KSW_DYN_FIELD_ID_TOK_P_SECURITY_ATTRIBUTES },
            { "_TOKEN.pSecurityAttributes", KSW_DYN_FIELD_ID_TOK_P_SECURITY_ATTRIBUTES },
            { "TokPackage", KSW_DYN_FIELD_ID_TOK_PACKAGE },
            { "_TOKEN.Package", KSW_DYN_FIELD_ID_TOK_PACKAGE },
            { "TokCapabilities", KSW_DYN_FIELD_ID_TOK_CAPABILITIES },
            { "_TOKEN.Capabilities", KSW_DYN_FIELD_ID_TOK_CAPABILITIES },
            { "TokCapabilityCount", KSW_DYN_FIELD_ID_TOK_CAPABILITY_COUNT },
            { "_TOKEN.CapabilityCount", KSW_DYN_FIELD_ID_TOK_CAPABILITY_COUNT },
            { "TokCapabilitiesHash", KSW_DYN_FIELD_ID_TOK_CAPABILITIES_HASH },
            { "_TOKEN.CapabilitiesHash", KSW_DYN_FIELD_ID_TOK_CAPABILITIES_HASH },
            { "TokLowboxNumberEntry", KSW_DYN_FIELD_ID_TOK_LOWBOX_NUMBER_ENTRY },
            { "_TOKEN.LowboxNumberEntry", KSW_DYN_FIELD_ID_TOK_LOWBOX_NUMBER_ENTRY },
            { "TokLowboxHandlesEntry", KSW_DYN_FIELD_ID_TOK_LOWBOX_HANDLES_ENTRY },
            { "_TOKEN.LowboxHandlesEntry", KSW_DYN_FIELD_ID_TOK_LOWBOX_HANDLES_ENTRY },
            { "TokPClaimAttributes", KSW_DYN_FIELD_ID_TOK_P_CLAIM_ATTRIBUTES },
            { "_TOKEN.pClaimAttributes", KSW_DYN_FIELD_ID_TOK_P_CLAIM_ATTRIBUTES },
            { "TokTrustLevelSid", KSW_DYN_FIELD_ID_TOK_TRUST_LEVEL_SID },
            { "_TOKEN.TrustLevelSid", KSW_DYN_FIELD_ID_TOK_TRUST_LEVEL_SID },
            { "TokTrustLinkedToken", KSW_DYN_FIELD_ID_TOK_TRUST_LINKED_TOKEN },
            { "_TOKEN.TrustLinkedToken", KSW_DYN_FIELD_ID_TOK_TRUST_LINKED_TOKEN },
            { "TokIntegrityLevelSidValue", KSW_DYN_FIELD_ID_TOK_INTEGRITY_LEVEL_SID_VALUE },
            { "_TOKEN.IntegrityLevelSidValue", KSW_DYN_FIELD_ID_TOK_INTEGRITY_LEVEL_SID_VALUE },
            { "TokTokenSidValues", KSW_DYN_FIELD_ID_TOK_TOKEN_SID_VALUES },
            { "_TOKEN.TokenSidValues", KSW_DYN_FIELD_ID_TOK_TOKEN_SID_VALUES },
            { "TokSessionObject", KSW_DYN_FIELD_ID_TOK_SESSION_OBJECT },
            { "_TOKEN.SessionObject", KSW_DYN_FIELD_ID_TOK_SESSION_OBJECT },
            { "TokVariablePart", KSW_DYN_FIELD_ID_TOK_VARIABLE_PART },
            { "_TOKEN.VariablePart", KSW_DYN_FIELD_ID_TOK_VARIABLE_PART },
            { "HtHandleContentionEvent", KSW_DYN_FIELD_ID_HT_HANDLE_CONTENTION_EVENT },
            { "HtTableCode", KSW_DYN_FIELD_ID_HT_TABLE_CODE },
            { "_HANDLE_TABLE.TableCode", KSW_DYN_FIELD_ID_HT_TABLE_CODE },
            { "HtHandleCount", KSW_DYN_FIELD_ID_HT_HANDLE_COUNT },
            { "_HANDLE_TABLE.HandleCount", KSW_DYN_FIELD_ID_HT_HANDLE_COUNT },
            { "HteLowValue", KSW_DYN_FIELD_ID_HTE_LOW_VALUE },
            { "_HANDLE_TABLE_ENTRY.LowValue", KSW_DYN_FIELD_ID_HTE_LOW_VALUE },
            { "OtName", KSW_DYN_FIELD_ID_OT_NAME },
            { "OtIndex", KSW_DYN_FIELD_ID_OT_INDEX },
            { "ObDecodeShift", KSW_DYN_FIELD_ID_OB_DECODE_SHIFT },
            { "ObAttributesShift", KSW_DYN_FIELD_ID_OB_ATTRIBUTES_SHIFT },
            { "KtInitialStack", KSW_DYN_FIELD_ID_KT_INITIAL_STACK },
            { "KtStackLimit", KSW_DYN_FIELD_ID_KT_STACK_LIMIT },
            { "KtStackBase", KSW_DYN_FIELD_ID_KT_STACK_BASE },
            { "KtKernelStack", KSW_DYN_FIELD_ID_KT_KERNEL_STACK },
            { "KtProcess", KSW_DYN_FIELD_ID_KT_PROCESS },
            { "_KTHREAD.Process", KSW_DYN_FIELD_ID_KT_PROCESS },
            { "EtCid", KSW_DYN_FIELD_ID_ET_CID },
            { "_ETHREAD.Cid", KSW_DYN_FIELD_ID_ET_CID },
            { "EtThreadListEntry", KSW_DYN_FIELD_ID_ET_THREAD_LIST_ENTRY },
            { "_ETHREAD.ThreadListEntry", KSW_DYN_FIELD_ID_ET_THREAD_LIST_ENTRY },
            { "EtStartAddress", KSW_DYN_FIELD_ID_ET_START_ADDRESS },
            { "_ETHREAD.StartAddress", KSW_DYN_FIELD_ID_ET_START_ADDRESS },
            { "EtWin32StartAddress", KSW_DYN_FIELD_ID_ET_WIN32_START_ADDRESS },
            { "_ETHREAD.Win32StartAddress", KSW_DYN_FIELD_ID_ET_WIN32_START_ADDRESS },
            { "KtReadOperationCount", KSW_DYN_FIELD_ID_KT_READ_OPERATION_COUNT },
            { "KtWriteOperationCount", KSW_DYN_FIELD_ID_KT_WRITE_OPERATION_COUNT },
            { "KtOtherOperationCount", KSW_DYN_FIELD_ID_KT_OTHER_OPERATION_COUNT },
            { "KtReadTransferCount", KSW_DYN_FIELD_ID_KT_READ_TRANSFER_COUNT },
            { "KtWriteTransferCount", KSW_DYN_FIELD_ID_KT_WRITE_TRANSFER_COUNT },
            { "KtOtherTransferCount", KSW_DYN_FIELD_ID_KT_OTHER_TRANSFER_COUNT },
            { "MmSectionControlArea", KSW_DYN_FIELD_ID_MM_SECTION_CONTROL_AREA },
            { "MmControlAreaListHead", KSW_DYN_FIELD_ID_MM_CONTROL_AREA_LIST_HEAD },
            { "MmControlAreaLock", KSW_DYN_FIELD_ID_MM_CONTROL_AREA_LOCK },
            { "AlpcCommunicationInfo", KSW_DYN_FIELD_ID_ALPC_COMMUNICATION_INFO },
            { "AlpcOwnerProcess", KSW_DYN_FIELD_ID_ALPC_OWNER_PROCESS },
            { "AlpcConnectionPort", KSW_DYN_FIELD_ID_ALPC_CONNECTION_PORT },
            { "AlpcServerCommunicationPort", KSW_DYN_FIELD_ID_ALPC_SERVER_COMMUNICATION_PORT },
            { "AlpcClientCommunicationPort", KSW_DYN_FIELD_ID_ALPC_CLIENT_COMMUNICATION_PORT },
            { "AlpcHandleTable", KSW_DYN_FIELD_ID_ALPC_HANDLE_TABLE },
            { "AlpcHandleTableLock", KSW_DYN_FIELD_ID_ALPC_HANDLE_TABLE_LOCK },
            { "AlpcAttributes", KSW_DYN_FIELD_ID_ALPC_ATTRIBUTES },
            { "AlpcAttributesFlags", KSW_DYN_FIELD_ID_ALPC_ATTRIBUTES_FLAGS },
            { "AlpcPortContext", KSW_DYN_FIELD_ID_ALPC_PORT_CONTEXT },
            { "AlpcPortObjectLock", KSW_DYN_FIELD_ID_ALPC_PORT_OBJECT_LOCK },
            { "AlpcSequenceNo", KSW_DYN_FIELD_ID_ALPC_SEQUENCE_NO },
            { "AlpcState", KSW_DYN_FIELD_ID_ALPC_STATE },
            { "LxPicoProc", KSW_DYN_FIELD_ID_LX_PICO_PROC },
            { "LxPicoProcInfo", KSW_DYN_FIELD_ID_LX_PICO_PROC_INFO },
            { "LxPicoProcInfoPID", KSW_DYN_FIELD_ID_LX_PICO_PROC_INFO_PID },
            { "LxPicoThrdInfo", KSW_DYN_FIELD_ID_LX_PICO_THRD_INFO },
            { "LxPicoThrdInfoTID", KSW_DYN_FIELD_ID_LX_PICO_THRD_INFO_TID },
            { "EpProtection", KSW_DYN_FIELD_ID_EP_PROTECTION },
            { "EpSignatureLevel", KSW_DYN_FIELD_ID_EP_SIGNATURE_LEVEL },
            { "EpSectionSignatureLevel", KSW_DYN_FIELD_ID_EP_SECTION_SIGNATURE_LEVEL },
            { "EgeGuid", KSW_DYN_FIELD_ID_EGE_GUID },
            { "EreGuidEntry", KSW_DYN_FIELD_ID_ERE_GUID_ENTRY },
            { "KldrInLoadOrderLinks", KSW_DYN_FIELD_ID_KLDR_IN_LOAD_ORDER_LINKS },
            { "_KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks", KSW_DYN_FIELD_ID_KLDR_IN_LOAD_ORDER_LINKS },
            { "KldrDllBase", KSW_DYN_FIELD_ID_KLDR_DLL_BASE },
            { "_KLDR_DATA_TABLE_ENTRY.DllBase", KSW_DYN_FIELD_ID_KLDR_DLL_BASE },
            { "KldrSizeOfImage", KSW_DYN_FIELD_ID_KLDR_SIZE_OF_IMAGE },
            { "_KLDR_DATA_TABLE_ENTRY.SizeOfImage", KSW_DYN_FIELD_ID_KLDR_SIZE_OF_IMAGE },
            { "KldrFullDllName", KSW_DYN_FIELD_ID_KLDR_FULL_DLL_NAME },
            { "_KLDR_DATA_TABLE_ENTRY.FullDllName", KSW_DYN_FIELD_ID_KLDR_FULL_DLL_NAME },
            { "KldrBaseDllName", KSW_DYN_FIELD_ID_KLDR_BASE_DLL_NAME },
            { "_KLDR_DATA_TABLE_ENTRY.BaseDllName", KSW_DYN_FIELD_ID_KLDR_BASE_DLL_NAME },
            { "KldrFlags", KSW_DYN_FIELD_ID_KLDR_FLAGS },
            { "_KLDR_DATA_TABLE_ENTRY.Flags", KSW_DYN_FIELD_ID_KLDR_FLAGS },
            { "DoDriverStart", KSW_DYN_FIELD_ID_DO_DRIVER_START },
            { "_DRIVER_OBJECT.DriverStart", KSW_DYN_FIELD_ID_DO_DRIVER_START },
            { "DoDriverSize", KSW_DYN_FIELD_ID_DO_DRIVER_SIZE },
            { "_DRIVER_OBJECT.DriverSize", KSW_DYN_FIELD_ID_DO_DRIVER_SIZE },
            { "DoDriverSection", KSW_DYN_FIELD_ID_DO_DRIVER_SECTION },
            { "_DRIVER_OBJECT.DriverSection", KSW_DYN_FIELD_ID_DO_DRIVER_SECTION },
            { "DoMajorFunction", KSW_DYN_FIELD_ID_DO_MAJOR_FUNCTION },
            { "_DRIVER_OBJECT.MajorFunction", KSW_DYN_FIELD_ID_DO_MAJOR_FUNCTION },
            { "DoFastIoDispatch", KSW_DYN_FIELD_ID_DO_FAST_IO_DISPATCH },
            { "_DRIVER_OBJECT.FastIoDispatch", KSW_DYN_FIELD_ID_DO_FAST_IO_DISPATCH },
            { "DoDriverUnload", KSW_DYN_FIELD_ID_DO_DRIVER_UNLOAD },
            { "_DRIVER_OBJECT.DriverUnload", KSW_DYN_FIELD_ID_DO_DRIVER_UNLOAD },
            // 卸载驱动记录字段：
            // - 输入：PDB profile generator 输出的短字段名或 type.field 名称；
            // - 处理：映射到 shared DynData ID，供后续 apply-profile(-ex) 写入 R0；
            // - 返回：本表不返回值，调用方通过 fieldIdOut 获得协议字段编号。
            { "UldName", KSW_DYN_FIELD_ID_ULD_NAME },
            { "_UNLOADED_DRIVERS.Name", KSW_DYN_FIELD_ID_ULD_NAME },
            { "UldStartAddress", KSW_DYN_FIELD_ID_ULD_START_ADDRESS },
            { "_UNLOADED_DRIVERS.StartAddress", KSW_DYN_FIELD_ID_ULD_START_ADDRESS },
            { "UldEndAddress", KSW_DYN_FIELD_ID_ULD_END_ADDRESS },
            { "_UNLOADED_DRIVERS.EndAddress", KSW_DYN_FIELD_ID_ULD_END_ADDRESS },
            { "UldCurrentTime", KSW_DYN_FIELD_ID_ULD_CURRENT_TIME },
            { "_UNLOADED_DRIVERS.CurrentTime", KSW_DYN_FIELD_ID_ULD_CURRENT_TIME },
            { "UldTypeSize", KSW_DYN_FIELD_ID_ULD_TYPE_SIZE },
            { "_UNLOADED_DRIVERS.TypeSize", KSW_DYN_FIELD_ID_ULD_TYPE_SIZE },
            { "RtlAvlBalancedRoot", KSW_DYN_FIELD_ID_RTL_AVL_BALANCED_ROOT },
            { "_RTL_AVL_TABLE.BalancedRoot", KSW_DYN_FIELD_ID_RTL_AVL_BALANCED_ROOT },
            { "RtlAvlOrderedPointer", KSW_DYN_FIELD_ID_RTL_AVL_ORDERED_POINTER },
            { "_RTL_AVL_TABLE.OrderedPointer", KSW_DYN_FIELD_ID_RTL_AVL_ORDERED_POINTER },
            { "RtlAvlWhichOrderedElement", KSW_DYN_FIELD_ID_RTL_AVL_WHICH_ORDERED_ELEMENT },
            { "_RTL_AVL_TABLE.WhichOrderedElement", KSW_DYN_FIELD_ID_RTL_AVL_WHICH_ORDERED_ELEMENT },
            { "RtlAvlNumberGenericTableElements", KSW_DYN_FIELD_ID_RTL_AVL_NUMBER_GENERIC_TABLE_ELEMENTS },
            { "_RTL_AVL_TABLE.NumberGenericTableElements", KSW_DYN_FIELD_ID_RTL_AVL_NUMBER_GENERIC_TABLE_ELEMENTS },
            { "RtlAvlDepthOfTree", KSW_DYN_FIELD_ID_RTL_AVL_DEPTH_OF_TREE },
            { "_RTL_AVL_TABLE.DepthOfTree", KSW_DYN_FIELD_ID_RTL_AVL_DEPTH_OF_TREE },
            { "RtlAvlRestartKey", KSW_DYN_FIELD_ID_RTL_AVL_RESTART_KEY },
            { "_RTL_AVL_TABLE.RestartKey", KSW_DYN_FIELD_ID_RTL_AVL_RESTART_KEY },
            { "RtlAvlDeleteCount", KSW_DYN_FIELD_ID_RTL_AVL_DELETE_COUNT },
            { "_RTL_AVL_TABLE.DeleteCount", KSW_DYN_FIELD_ID_RTL_AVL_DELETE_COUNT },
            { "RtlAvlTypeSize", KSW_DYN_FIELD_ID_RTL_AVL_TYPE_SIZE },
            { "_RTL_AVL_TABLE.TypeSize", KSW_DYN_FIELD_ID_RTL_AVL_TYPE_SIZE },
            { "PiDdbDriverName", KSW_DYN_FIELD_ID_PIDDB_DRIVER_NAME },
            { "_PIDDB_CACHE_ENTRY.DriverName", KSW_DYN_FIELD_ID_PIDDB_DRIVER_NAME },
            { "PiDdbTimeDateStamp", KSW_DYN_FIELD_ID_PIDDB_TIME_DATE_STAMP },
            { "_PIDDB_CACHE_ENTRY.TimeDateStamp", KSW_DYN_FIELD_ID_PIDDB_TIME_DATE_STAMP },
            { "PiDdbLoadStatus", KSW_DYN_FIELD_ID_PIDDB_LOAD_STATUS },
            { "_PIDDB_CACHE_ENTRY.LoadStatus", KSW_DYN_FIELD_ID_PIDDB_LOAD_STATUS },
            { "PiDdbTypeSize", KSW_DYN_FIELD_ID_PIDDB_TYPE_SIZE },
            { "_PIDDB_CACHE_ENTRY.TypeSize", KSW_DYN_FIELD_ID_PIDDB_TYPE_SIZE },
            { "PspCidTable", KSW_DYN_FIELD_ID_KG_PSP_CID_TABLE },
            { "PsLoadedModuleList", KSW_DYN_FIELD_ID_KG_PS_LOADED_MODULE_LIST },
            { "MmUnloadedDrivers", KSW_DYN_FIELD_ID_KG_MM_UNLOADED_DRIVERS },
            { "PiDDBCacheTable", KSW_DYN_FIELD_ID_KG_PIDDB_CACHE_TABLE },
            { "PiDDBLock", KSW_DYN_FIELD_ID_KG_PIDDB_LOCK },
            // Kernel Global RVA 映射：
            // - 输入：PDB profile pack 中的 Shadow SSDT 全局符号名；
            // - 处理：映射到 shared DynData 字段 ID，避免 EX apply 将该项计入 ignored；
            // - 返回：本表不返回值，调用方通过 fieldIdOut 获得协议字段编号。
            { "KeServiceDescriptorTableShadow", KSW_DYN_FIELD_ID_KG_KE_SERVICE_DESCRIPTOR_TABLE_SHADOW },
            { "KgKeServiceDescriptorTableShadow", KSW_DYN_FIELD_ID_KG_KE_SERVICE_DESCRIPTOR_TABLE_SHADOW },
            { "MmLastUnloadedDriver", KSW_DYN_FIELD_ID_KG_MM_LAST_UNLOADED_DRIVER },
            { "PspCreateProcessNotifyRoutine", KSW_DYN_FIELD_ID_CB_PSP_CREATE_PROCESS_NOTIFY_ROUTINE },
            { "PspCreateThreadNotifyRoutine", KSW_DYN_FIELD_ID_CB_PSP_CREATE_THREAD_NOTIFY_ROUTINE },
            { "PspLoadImageNotifyRoutine", KSW_DYN_FIELD_ID_CB_PSP_LOAD_IMAGE_NOTIFY_ROUTINE },
            { "PspNotifyEnableMask", KSW_DYN_FIELD_ID_CB_PSP_NOTIFY_ENABLE_MASK },
            { "CmCallbackListHead", KSW_DYN_FIELD_ID_CB_CM_CALLBACK_LIST_HEAD },
            { "_OBJECT_TYPE.CallbackList", KSW_DYN_FIELD_ID_CB_OBJECT_TYPE_CALLBACK_LIST },
            { "_CALLBACK_ENTRY_ITEM.EntryList", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_ENTRY_LIST },
            { "_CALLBACK_ENTRY_ITEM.EntryItemList", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_ENTRY_LIST },
            { "_CALLBACK_ENTRY_ITEM.PreOperation", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_PRE_OPERATION },
            { "_CALLBACK_ENTRY_ITEM.PostOperation", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_POST_OPERATION },
            { "_CALLBACK_ENTRY_ITEM.Operations", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_OPERATIONS },
            { "_CALLBACK_ENTRY_ITEM.CallbackEntry", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_CALLBACK_ENTRY },
            { "_CALLBACK_ENTRY.Altitude", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ALTITUDE },
            { "_CALLBACK_ENTRY.RegistrationContext", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_REGISTRATION_CONTEXT }
        };

        const auto iterator = kFieldIds.find(fieldName.toStdString());
        if (iterator == kFieldIds.end())
        {
            fieldIdOut = 0U;
            return false;
        }

        fieldIdOut = iterator->second;
        return true;
    }


    // fieldIdIsCallbackGlobal：
    // - 输入 fieldId：共享协议字段 ID；
    // - 处理：识别 callbackItems/v2 使用的 callback 全局 RVA；
    // - 返回：true 表示该字段应作为 callback GlobalRva 发送给 EX IOCTL。
    bool fieldIdIsCallbackGlobal(const std::uint32_t fieldId)
    {
        switch (fieldId)
        {
        case KSW_DYN_FIELD_ID_CB_PSP_CREATE_PROCESS_NOTIFY_ROUTINE:
        case KSW_DYN_FIELD_ID_CB_PSP_CREATE_THREAD_NOTIFY_ROUTINE:
        case KSW_DYN_FIELD_ID_CB_PSP_LOAD_IMAGE_NOTIFY_ROUTINE:
        case KSW_DYN_FIELD_ID_CB_PSP_NOTIFY_ENABLE_MASK:
        case KSW_DYN_FIELD_ID_CB_CM_CALLBACK_LIST_HEAD:
            return true;
        default:
            return false;
        }
    }

    // fieldIdIsKernelGlobal：
    // - 输入 fieldId：共享协议字段 ID；
    // - 处理：识别 v3 typed items 使用的内核全局 RVA；
    // - 返回：true 表示该字段应作为非 callback GlobalRva 发送给 EX IOCTL。
    bool fieldIdIsKernelGlobal(const std::uint32_t fieldId)
    {
        switch (fieldId)
        {
        case KSW_DYN_FIELD_ID_KG_PSP_CID_TABLE:
        case KSW_DYN_FIELD_ID_KG_PS_LOADED_MODULE_LIST:
        case KSW_DYN_FIELD_ID_KG_MM_UNLOADED_DRIVERS:
        case KSW_DYN_FIELD_ID_KG_PIDDB_CACHE_TABLE:
        case KSW_DYN_FIELD_ID_KG_PIDDB_LOCK:
        case KSW_DYN_FIELD_ID_KG_KE_SERVICE_DESCRIPTOR_TABLE_SHADOW:
        case KSW_DYN_FIELD_ID_KG_MM_LAST_UNLOADED_DRIVER:
            return true;
        default:
            return false;
        }
    }

    // fieldIdIsGlobalRva：
    // - 输入 fieldId：共享协议字段 ID；
    // - 处理：汇总 callback 和 kernel global 两类 GlobalRva 项；
    // - 返回：true 表示字段值应按 RVA 校验和提交。
    bool fieldIdIsGlobalRva(const std::uint32_t fieldId)
    {
        return fieldIdIsCallbackGlobal(fieldId) || fieldIdIsKernelGlobal(fieldId);
    }

    // fieldIdIsCallbackOffset：
    // - 输入 fieldId：共享协议字段 ID；
    // - 处理：识别 callbackItems/v2 使用的 callback 结构偏移；
    // - 返回：true 表示该字段应作为 callback StructOffset 发送给 EX IOCTL。
    bool fieldIdIsCallbackOffset(const std::uint32_t fieldId)
    {
        switch (fieldId)
        {
        case KSW_DYN_FIELD_ID_CB_OBJECT_TYPE_CALLBACK_LIST:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_ENTRY_LIST:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_PRE_OPERATION:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_POST_OPERATION:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_OPERATIONS:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_CALLBACK_ENTRY:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ALTITUDE:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_REGISTRATION_CONTEXT:
            return true;
        default:
            return false;
        }
    }

    // fieldIdIsLxcoreOffset：
    // - 输入 fieldId：共享协议字段 ID；
    // - 处理：识别 System Informer lxcore profile 字段，当前 ntoskrnl PDB EX apply 不承载这些字段；
    // - 返回：true 表示该字段不能放入 ntoskrnl v3 StructOffset typed item。
    bool fieldIdIsLxcoreOffset(const std::uint32_t fieldId)
    {
        switch (fieldId)
        {
        case KSW_DYN_FIELD_ID_LX_PICO_PROC:
        case KSW_DYN_FIELD_ID_LX_PICO_PROC_INFO:
        case KSW_DYN_FIELD_ID_LX_PICO_PROC_INFO_PID:
        case KSW_DYN_FIELD_ID_LX_PICO_THRD_INFO:
        case KSW_DYN_FIELD_ID_LX_PICO_THRD_INFO_TID:
            return true;
        default:
            return false;
        }
    }

    // fieldIdIsStructOffset：
    // - 输入 fieldId：共享协议字段 ID；
    // - 处理：排除 GlobalRva 和 lxcore-only 字段后，允许已知字段通过 StructOffset 路径应用；
    // - 返回：true 表示字段值应按结构偏移校验和提交。
    bool fieldIdIsStructOffset(const std::uint32_t fieldId)
    {
        return fieldId != 0U &&
            fieldId <= KSW_DYN_FIELD_ID_MAX &&
            !fieldIdIsGlobalRva(fieldId) &&
            !fieldIdIsLxcoreOffset(fieldId);
    }

    QString callbackItemKindText(const QString& kindText)
    {
        const QString normalized = kindText.trimmed();
        if (normalized.compare(QStringLiteral("GlobalRva"), Qt::CaseInsensitive) == 0)
        {
            return QStringLiteral("GlobalRva");
        }
        if (normalized.compare(QStringLiteral("StructOffset"), Qt::CaseInsensitive) == 0)
        {
            return QStringLiteral("StructOffset");
        }
        if (normalized.compare(QStringLiteral("TypeSize"), Qt::CaseInsensitive) == 0)
        {
            return QStringLiteral("TypeSize");
        }
        return normalized;
    }

    // profileContainsExItem：
    // - 输入 profile/fieldId：当前本地 profile 和候选字段 ID；
    // - 处理：扫描已展开的 EX item，避免 callbackItems 与 v3 items 重复提交；
    // - 返回：true 表示字段 ID 已存在。
    bool profileContainsExItem(const LocalPdbProfile& profile, const std::uint32_t fieldId)
    {
        return std::any_of(
            profile.applyExInput.items.begin(),
            profile.applyExInput.items.end(),
            [fieldId](const ksword::ark::DynDataProfileExItem& item) {
                return item.itemId == fieldId;
            });
    }

    // appendProfileExItem：
    // - 输入 profile/fieldId/itemKind/value/required：待追加的 typed item 数据；
    // - 处理：设置 EX IOCTL 所需 itemKind、value 和 callback/required 标志；
    // - 返回：无返回值，profile.applyExInput.items 会按需追加一项。
    void appendProfileExItem(
        LocalPdbProfile& profile,
        const std::uint32_t fieldId,
        const std::uint32_t itemKind,
        const std::uint32_t value,
        const bool required)
    {
        ksword::ark::DynDataProfileExItem exItem{};
        exItem.itemId = fieldId;
        exItem.itemKind = itemKind;
        exItem.value = value;
        exItem.flags = required ? KSW_DYN_PROFILE_EX_ITEM_FLAG_REQUIRED : 0U;
        if (fieldIdIsCallbackGlobal(fieldId) || fieldIdIsCallbackOffset(fieldId))
        {
            exItem.flags |= KSW_DYN_PROFILE_EX_ITEM_FLAG_CALLBACK;
        }
        profile.applyExInput.items.push_back(exItem);
        profile.exAppliedCount = static_cast<std::uint32_t>(profile.applyExInput.items.size());
    }

    // parseProfileUInt32 前置声明：
    // - 输入 value：JSON 数值或字符串；
    // - 处理/返回：实际解析逻辑位于下方定义，此处只允许 callbackItems 解析 helper 提前调用。
    bool parseProfileUInt32(const QJsonValue& value, std::uint32_t& valueOut);

    bool loadCallbackItemsFromJson(
        const QJsonArray& callbackItemsArray,
        LocalPdbProfile& profile,
        QStringList& diagnostics,
        bool& hasCallbackItemsOut)
    {
        hasCallbackItemsOut = false;
        if (callbackItemsArray.isEmpty())
        {
            return true;
        }

        hasCallbackItemsOut = true;
        std::array<bool, KSW_DYN_FIELD_ID_MAX + 1U> seenFieldIds{};
        for (const QJsonValue& itemValue : callbackItemsArray)
        {
            if (!itemValue.isObject())
            {
                diagnostics << kernelText("kernel.dyndata.profile.callback.non_object", QStringLiteral("callbackItems 包含非对象项，已忽略。"));
                continue;
            }

            const QJsonObject itemObject = itemValue.toObject();
            const QString itemName = itemObject.value(QStringLiteral("name")).toString().trimmed();
            const QString itemKind = callbackItemKindText(itemObject.value(QStringLiteral("kind")).toString());
            std::uint32_t fieldId = 0U;
            if (!fieldIdForProfileName(itemName, fieldId))
            {
                profile.ignoredUnknownFields += 1U;
                continue;
            }

            std::uint32_t value = 0U;
            if (!parseProfileUInt32(itemObject.value(QStringLiteral("value")), value))
            {
                diagnostics << kernelText("kernel.dyndata.profile.callback.parse_failed", QStringLiteral("callbackItems 解析失败: %1")).arg(itemName);
                return false;
            }

            if (fieldId >= seenFieldIds.size() || seenFieldIds[fieldId])
            {
                diagnostics << kernelText("kernel.dyndata.profile.callback.duplicate", QStringLiteral("callbackItems 含重复字段: %1")).arg(itemName);
                return false;
            }
            seenFieldIds[fieldId] = true;

            if (itemKind == QStringLiteral("GlobalRva"))
            {
                if (!fieldIdIsCallbackGlobal(fieldId))
                {
                    diagnostics << kernelText("kernel.dyndata.profile.callback.kind_global_mismatch", QStringLiteral("callbackItems 语义不匹配: %1 不是 global")).arg(itemName);
                    return false;
                }
                if (value == 0U || value > KSW_DYN_PROFILE_GLOBAL_RVA_MAX)
                {
                    diagnostics << kernelText("kernel.dyndata.profile.callback.global_rva_out_of_range", QStringLiteral("callbackItems global RVA 越界: %1")).arg(itemName);
                    return false;
                }
                ksword::ark::DynDataProfileExItem exItem{};
                exItem.itemId = fieldId;
                exItem.itemKind = KSW_DYN_PROFILE_EX_ITEM_KIND_GLOBAL_RVA;
                exItem.value = value;
                exItem.flags = KSW_DYN_PROFILE_EX_ITEM_FLAG_REQUIRED | KSW_DYN_PROFILE_EX_ITEM_FLAG_CALLBACK;
                profile.applyExInput.items.push_back(exItem);
            }
            else if (itemKind == QStringLiteral("StructOffset"))
            {
                if (!fieldIdIsCallbackOffset(fieldId))
                {
                    diagnostics << kernelText("kernel.dyndata.profile.callback.kind_struct_offset_mismatch", QStringLiteral("callbackItems 语义不匹配: %1 不是 struct offset")).arg(itemName);
                    return false;
                }
                ksword::ark::DynDataProfileExItem exItem{};
                exItem.itemId = fieldId;
                exItem.itemKind = KSW_DYN_PROFILE_EX_ITEM_KIND_STRUCT_OFFSET;
                exItem.value = value;
                exItem.flags = KSW_DYN_PROFILE_EX_ITEM_FLAG_REQUIRED | KSW_DYN_PROFILE_EX_ITEM_FLAG_CALLBACK;
                profile.applyExInput.items.push_back(exItem);
            }
            else if (itemKind == QStringLiteral("TypeSize"))
            {
                if (!fieldIdIsStructOffset(fieldId))
                {
                    diagnostics << kernelText("kernel.dyndata.profile.callback.kind_type_size_mismatch", QStringLiteral("callbackItems 语义不匹配: %1 不是 type size")).arg(itemName);
                    return false;
                }
                appendProfileExItem(profile, fieldId, KSW_DYN_PROFILE_EX_ITEM_KIND_STRUCT_OFFSET, value, true);
            }
            else
            {
                diagnostics << kernelText("kernel.dyndata.profile.callback.kind_unsupported", QStringLiteral("callbackItems kind 不支持: %1")).arg(itemName);
                return false;
            }

            profile.callbackItemCount += 1U;
        }

        profile.exAppliedCount = static_cast<std::uint32_t>(profile.applyExInput.items.size());
        return true;
    }

    // loadTypedItemsFromJson：
    // - 输入 typedItemsArray/profile/diagnostics/hasTypedItemsOut：v3 items 数组、输出 profile 和诊断容器；
    // - 处理：解析 name/kind/value，把 StructOffset 与 GlobalRva 统一展开为 EX IOCTL item；
    // - 返回：true 表示 typed items 可用或为空；false 表示命中项语义/范围错误。
    bool loadTypedItemsFromJson(
        const QJsonArray& typedItemsArray,
        LocalPdbProfile& profile,
        QStringList& diagnostics,
        bool& hasTypedItemsOut)
    {
        hasTypedItemsOut = false;
        if (typedItemsArray.isEmpty())
        {
            return true;
        }

        hasTypedItemsOut = true;
        std::array<bool, KSW_DYN_FIELD_ID_MAX + 1U> seenFieldIds{};
        for (const QJsonValue& itemValue : typedItemsArray)
        {
            if (!itemValue.isObject())
            {
                diagnostics << kernelText("kernel.dyndata.profile.typed.non_object", QStringLiteral("typed items 包含非对象项，已忽略。"));
                continue;
            }

            const QJsonObject itemObject = itemValue.toObject();
            const QString itemName = itemObject.value(QStringLiteral("name")).toString().trimmed();
            const QString itemKind = callbackItemKindText(itemObject.value(QStringLiteral("kind")).toString());
            const bool required = itemObject.value(QStringLiteral("required")).toBool(false);

            std::uint32_t fieldId = 0U;
            if (!fieldIdForProfileName(itemName, fieldId))
            {
                profile.ignoredUnknownFields += 1U;
                continue;
            }

            std::uint32_t value = 0U;
            if (!parseProfileUInt32(itemObject.value(QStringLiteral("value")), value))
            {
                diagnostics << kernelText("kernel.dyndata.profile.typed.parse_failed", QStringLiteral("typed items 解析失败: %1")).arg(itemName);
                return false;
            }

            if (fieldId >= seenFieldIds.size() || seenFieldIds[fieldId] || profileContainsExItem(profile, fieldId))
            {
                diagnostics << kernelText("kernel.dyndata.profile.typed.duplicate", QStringLiteral("typed items 含重复字段: %1")).arg(itemName);
                return false;
            }
            seenFieldIds[fieldId] = true;

            if (itemKind == QStringLiteral("GlobalRva"))
            {
                if (!fieldIdIsGlobalRva(fieldId))
                {
                    diagnostics << kernelText("kernel.dyndata.profile.typed.kind_global_rva_mismatch", QStringLiteral("typed items 语义不匹配: %1 不是 global RVA")).arg(itemName);
                    return false;
                }
                if (value == 0U || value > KSW_DYN_PROFILE_GLOBAL_RVA_MAX)
                {
                    diagnostics << kernelText("kernel.dyndata.profile.typed.global_rva_out_of_range", QStringLiteral("typed items global RVA 越界: %1")).arg(itemName);
                    return false;
                }
                appendProfileExItem(profile, fieldId, KSW_DYN_PROFILE_EX_ITEM_KIND_GLOBAL_RVA, value, required);
            }
            else if (itemKind == QStringLiteral("StructOffset"))
            {
                if (!fieldIdIsStructOffset(fieldId))
                {
                    diagnostics << kernelText("kernel.dyndata.profile.typed.kind_struct_offset_mismatch", QStringLiteral("typed items 语义不匹配: %1 不是 struct offset")).arg(itemName);
                    return false;
                }
                if (value == 0xFFFFFFFFU || value > KSW_DYN_PROFILE_OFFSET_MAX)
                {
                    diagnostics << kernelText("kernel.dyndata.profile.typed.struct_offset_out_of_range", QStringLiteral("typed items struct offset 越界: %1")).arg(itemName);
                    return false;
                }
                appendProfileExItem(profile, fieldId, KSW_DYN_PROFILE_EX_ITEM_KIND_STRUCT_OFFSET, value, required);
            }
            else if (itemKind == QStringLiteral("TypeSize"))
            {
                if (!fieldIdIsStructOffset(fieldId))
                {
                    diagnostics << kernelText("kernel.dyndata.profile.typed.kind_type_size_mismatch", QStringLiteral("typed items 语义不匹配: %1 不是 type size")).arg(itemName);
                    return false;
                }
                if (value == 0U || value > KSW_DYN_PROFILE_OFFSET_MAX)
                {
                    diagnostics << kernelText("kernel.dyndata.profile.typed.type_size_out_of_range", QStringLiteral("typed items type size 越界: %1")).arg(itemName);
                    return false;
                }
                appendProfileExItem(profile, fieldId, KSW_DYN_PROFILE_EX_ITEM_KIND_STRUCT_OFFSET, value, required);
            }
            else
            {
                diagnostics << kernelText("kernel.dyndata.profile.typed.kind_unsupported", QStringLiteral("typed items kind 不支持: %1")).arg(itemName);
                return false;
            }
            profile.typedItemCount += 1U;
        }

        return true;
    }

    // parseProfileUInt32：
    // - 输入 value：JSON 数值或 0x 前缀字符串；
    // - 处理：进行 32-bit 无符号范围校验；
    // - 返回：成功解析 true，失败 false。
    bool parseProfileUInt32(const QJsonValue& value, std::uint32_t& valueOut)
    {
        bool ok = false;
        qulonglong parsedValue = 0ULL;

        valueOut = 0U;
        if (value.isString())
        {
            QString text = value.toString().trimmed();
            int base = 10;
            if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
            {
                text = text.mid(2);
                base = 16;
            }
            parsedValue = text.toULongLong(&ok, base);
        }
        else if (value.isDouble())
        {
            const double numericValue = value.toDouble();
            if (numericValue >= 0.0 && numericValue <= static_cast<double>(std::numeric_limits<std::uint32_t>::max()))
            {
                parsedValue = static_cast<qulonglong>(numericValue);
                ok = true;
            }
        }

        if (!ok || parsedValue > static_cast<qulonglong>(std::numeric_limits<std::uint32_t>::max()))
        {
            return false;
        }

        valueOut = static_cast<std::uint32_t>(parsedValue);
        return true;
    }

    template <std::size_t Size>
    void copyV4Utf8(char (&destination)[Size], const QString& source)
    {
        static_assert(Size > 0U);
        const QByteArray bytes = source.toUtf8();
        const std::size_t copyLength = std::min<std::size_t>(Size - 1U, static_cast<std::size_t>(bytes.size()));
        std::memset(destination, 0, Size);
        if (copyLength != 0U)
        {
            std::memcpy(destination, bytes.constData(), copyLength);
        }
    }

    template <std::size_t Size>
    void copyV4Wide(wchar_t (&destination)[Size], const std::wstring& source)
    {
        static_assert(Size > 0U);
        const std::size_t copyLength = std::min<std::size_t>(Size - 1U, source.size());
        std::fill(std::begin(destination), std::end(destination), L'\0');
        if (copyLength != 0U)
        {
            std::copy_n(source.begin(), copyLength, destination);
        }
    }

    bool v4ItemIdSupported(const std::uint32_t itemId)
    {
        return KswordArkDynDataV4ItemIdSupported(itemId) != 0;
    }

    bool loadV4ItemsFromJson(
        const QJsonArray& itemArray,
        const QJsonArray& groupArray,
        const ksword::ark::ArkDynModuleIdentity& currentIdentity,
        const QString& profileName,
        const QString& pdbName,
        const QString& pdbGuid,
        const std::uint32_t pdbAge,
        LocalPdbProfile& profile,
        QStringList& diagnostics)
    {
        if (itemArray.isEmpty() || groupArray.isEmpty() ||
            itemArray.size() > static_cast<int>(KSW_DYN_V4_MAX_ITEMS_PER_MODULE) ||
            groupArray.size() > static_cast<int>(KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE))
        {
            diagnostics << kernelText("kernel.dyndata.pack.v4.invalid", QStringLiteral("v4 pack items/capabilityGroups 无效。"));
            return false;
        }

        std::array<bool, KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE + 1U> seenGroups{};
        std::unordered_map<std::uint32_t, std::pair<std::uint32_t, std::uint32_t>> expectedCounts;
        profile.applyV4Input.capabilityGroups.clear();
        profile.applyV4Input.items.clear();
        for (const QJsonValue& groupValue : groupArray)
        {
            if (!groupValue.isObject())
            {
                diagnostics << kernelText("kernel.dyndata.pack.v4.invalid", QStringLiteral("v4 pack items/capabilityGroups 无效。"));
                return false;
            }
            const QJsonObject groupObject = groupValue.toObject();
            std::uint32_t groupId = 0U;
            std::uint32_t flags = 0U;
            std::uint32_t requiredCount = 0U;
            std::uint32_t optionalCount = 0U;
            if (!parseProfileUInt32(groupObject.value(QStringLiteral("groupId")), groupId) ||
                !parseProfileUInt32(groupObject.value(QStringLiteral("flags")), flags) ||
                !parseProfileUInt32(groupObject.value(QStringLiteral("requiredItemCount")), requiredCount) ||
                !parseProfileUInt32(groupObject.value(QStringLiteral("optionalItemCount")), optionalCount) ||
                groupId == 0U || groupId > KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE || seenGroups[groupId])
            {
                diagnostics << kernelText("kernel.dyndata.pack.v4.invalid", QStringLiteral("v4 pack items/capabilityGroups 无效。"));
                return false;
            }
            seenGroups[groupId] = true;
            KSW_DYN_V4_CAPABILITY_GROUP_PACKET group{};
            group.groupId = groupId;
            group.flags = flags;
            group.requiredItemCount = requiredCount;
            group.optionalItemCount = optionalCount;
            copyV4Utf8(group.groupName, groupObject.value(QStringLiteral("groupName")).toString());
            profile.applyV4Input.capabilityGroups.push_back(group);
            expectedCounts[groupId] = {requiredCount, optionalCount};
        }

        std::array<bool, 2048U> seenItems{};
        std::unordered_map<std::uint32_t, std::pair<std::uint32_t, std::uint32_t>> actualCounts;
        for (const QJsonValue& itemValue : itemArray)
        {
            if (!itemValue.isObject())
            {
                diagnostics << kernelText("kernel.dyndata.pack.v4.invalid", QStringLiteral("v4 pack items/capabilityGroups 无效。"));
                return false;
            }
            const QJsonObject itemObject = itemValue.toObject();
            std::uint32_t itemId = 0U;
            std::uint32_t itemKind = 0U;
            std::uint32_t flags = 0U;
            std::uint32_t groupId = 0U;
            std::uint32_t valueLow = 0U;
            std::uint32_t valueHigh = 0U;
            std::uint32_t aux[4]{};
            if (!parseProfileUInt32(itemObject.value(QStringLiteral("itemId")), itemId) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("itemKind")), itemKind) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("flags")), flags) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("capabilityGroupId")), groupId) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("valueLow")), valueLow) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("valueHigh")), valueHigh) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("aux0")), aux[0]) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("aux1")), aux[1]) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("aux2")), aux[2]) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("aux3")), aux[3]) ||
                !v4ItemIdSupported(itemId) || itemId >= seenItems.size() || seenItems[itemId] ||
                itemKind < KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET || itemKind > KSW_DYN_V4_ITEM_KIND_LIST_HEAD_GLOBAL ||
                (flags != KSW_DYN_V4_ITEM_FLAG_REQUIRED && flags != KSW_DYN_V4_ITEM_FLAG_OPTIONAL) ||
                groupId == 0U || !seenGroups[groupId])
            {
                diagnostics << kernelText("kernel.dyndata.pack.v4.invalid", QStringLiteral("v4 pack items/capabilityGroups 无效。"));
                return false;
            }
            seenItems[itemId] = true;
            KSW_DYN_V4_ITEM_PACKET item{};
            item.itemId = itemId;
            item.itemKind = itemKind;
            item.flags = flags;
            item.capabilityGroupId = groupId;
            item.valueLow = valueLow;
            item.valueHigh = valueHigh;
            item.aux0 = aux[0];
            item.aux1 = aux[1];
            item.aux2 = aux[2];
            item.aux3 = aux[3];
            profile.applyV4Input.items.push_back(item);
            // v4 core items are the single source of truth.  Derive the
            // legacy EX projection in memory so existing field consumers keep
            // working without storing a second offset array in the pack.
            if (itemId >= 1U && itemId <= KSW_DYN_FIELD_ID_MAX &&
                (itemKind == KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET ||
                 itemKind == KSW_DYN_V4_ITEM_KIND_TYPE_SIZE ||
                 itemKind == KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA ||
                 itemKind == KSW_DYN_V4_ITEM_KIND_LIST_HEAD_GLOBAL))
            {
                const std::uint32_t exKind =
                    (itemKind == KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA ||
                     itemKind == KSW_DYN_V4_ITEM_KIND_LIST_HEAD_GLOBAL)
                    ? KSW_DYN_PROFILE_EX_ITEM_KIND_GLOBAL_RVA
                    : KSW_DYN_PROFILE_EX_ITEM_KIND_STRUCT_OFFSET;
                appendProfileExItem(
                    profile,
                    itemId,
                    exKind,
                    valueLow,
                    (flags & KSW_DYN_V4_ITEM_FLAG_REQUIRED) != 0U);
            }
            auto& counts = actualCounts[groupId];
            if ((flags & KSW_DYN_V4_ITEM_FLAG_REQUIRED) != 0U)
            {
                counts.first += 1U;
            }
            else
            {
                counts.second += 1U;
            }
        }
        for (const auto& expected : expectedCounts)
        {
            const auto actual = actualCounts[expected.first];
            if (actual != expected.second)
            {
                diagnostics << kernelText("kernel.dyndata.pack.v4.invalid", QStringLiteral("v4 pack items/capabilityGroups 计数不一致。"));
                return false;
            }
        }

        profile.applyV4Input.flags = 0U;
        profile.applyV4Input.module.image.present = currentIdentity.present ? 1UL : 0UL;
        profile.applyV4Input.module.image.classId = currentIdentity.classId;
        profile.applyV4Input.module.image.machine = currentIdentity.machine;
        profile.applyV4Input.module.image.timeDateStamp = currentIdentity.timeDateStamp;
        profile.applyV4Input.module.image.sizeOfImage = currentIdentity.sizeOfImage;
        profile.applyV4Input.module.image.imageBase = currentIdentity.imageBase;
        copyV4Wide(profile.applyV4Input.module.image.moduleName, currentIdentity.moduleName);
        copyV4Utf8(profile.applyV4Input.module.profileName, profileName);
        copyV4Utf8(profile.applyV4Input.module.pdb.pdbName, pdbName);
        copyV4Utf8(profile.applyV4Input.module.pdb.pdbGuid, pdbGuid);
        profile.applyV4Input.module.pdb.pdbAge = pdbAge;
        profile.applyExInput.profileName = profileName.toStdString();
        profile.applyExInput.pdbName = pdbName.toStdString();
        profile.applyExInput.pdbGuid = pdbGuid.toStdString();
        profile.applyExInput.pdbAge = pdbAge;
        profile.applyExInput.ntoskrnl = currentIdentity;
        profile.v4ItemCount = static_cast<std::uint32_t>(profile.applyV4Input.items.size());
        return true;
    }

    // profileClassIdFromText：
    // - 输入 classText：JSON module.class；
    // - 处理：转换到 R0 profile class id；
    // - 返回：成功 true，未知 class false。
    bool profileClassIdFromText(const QString& classText, std::uint32_t& classIdOut)
    {
        const QString normalized = classText.trimmed().toLower();
        if (normalized == QStringLiteral("ntoskrnl") ||
            normalized == QStringLiteral("ntoskrnl.exe") ||
            normalized == QStringLiteral("ntkrnlmp") ||
            normalized == QStringLiteral("ntkrnlmp.exe"))
        {
            classIdOut = KSW_DYN_PROFILE_CLASS_NTOSKRNL;
            return true;
        }
        if (normalized == QStringLiteral("ntkrla57") || normalized == QStringLiteral("ntkrla57.exe"))
        {
            classIdOut = KSW_DYN_PROFILE_CLASS_NTKRLA57;
            return true;
        }
        if (normalized == QStringLiteral("fltmgr") || normalized == QStringLiteral("fltmgr.sys"))
        {
            classIdOut = KSW_DYN_PROFILE_CLASS_FLTMGR;
            return true;
        }
        if (normalized == QStringLiteral("ci") ||
            normalized == QStringLiteral("ci.dll") ||
            normalized == QStringLiteral("ci.sys"))
        {
            classIdOut = KSW_DYN_PROFILE_CLASS_CI;
            return true;
        }

        classIdOut = 0U;
        return false;
    }

    // profileClassIdFromJsonValue：
    // - 输入 value：pack profile 中的 moduleClassId；
    // - 处理：解析 uint32 并限制到已知 class；
    // - 返回：成功 true，失败 false。
    bool profileClassIdFromJsonValue(const QJsonValue& value, std::uint32_t& classIdOut)
    {
        std::uint32_t parsedValue = 0U;
        if (!parseProfileUInt32(value, parsedValue))
        {
            classIdOut = 0U;
            return false;
        }

        switch (parsedValue)
        {
        case KSW_DYN_PROFILE_CLASS_NTOSKRNL:
        case KSW_DYN_PROFILE_CLASS_NTKRLA57:
        case KSW_DYN_PROFILE_CLASS_LXCORE:
        case KSW_DYN_PROFILE_CLASS_FLTMGR:
        case KSW_DYN_PROFILE_CLASS_CI:
            classIdOut = parsedValue;
            return true;
        default:
            classIdOut = 0U;
            return false;
        }
    }

    // appendUniquePath：
    // - 输入 paths/pathText：待维护列表和候选路径；
    // - 处理：清理路径并进行大小写不敏感去重；
    // - 返回：无，paths 按需追加。
    void appendUniquePath(QStringList& paths, const QString& pathText)
    {
        const QString trimmed = pathText.trimmed();
        if (trimmed.isEmpty())
        {
            return;
        }

        const QString cleaned = QDir::cleanPath(trimmed);
        if (!cleaned.isEmpty() && !paths.contains(cleaned, Qt::CaseInsensitive))
        {
            paths << cleaned;
        }
    }

    // profilePackSearchPaths：
    // - 输入：无；
    // - 处理：优先读取程序目录 pack，并允许环境变量指定调试 pack；
    // - 返回：候选 pack 文件路径列表，不保证存在。
    QStringList profilePackSearchPaths()
    {
        QStringList paths;
        appendUniquePath(paths, qEnvironmentVariable("KSWORD_ARK_PROFILE_PACK"));
        appendUniquePath(paths, QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("profiles/ark_dyndata_pack_v4.json")));
        appendUniquePath(paths, QDir::current().filePath(QStringLiteral("profiles/ark_dyndata_pack_v4.json")));
        return paths;
    }

    // profileSearchDirectories：
    // - 输入：无；
    // - 处理：仅当 KSWORD_ARK_PROFILE_DIR 显式设置时启用散落 JSON 调试 fallback；
    // - 返回：候选目录列表，不保证目录存在。
    QStringList profileSearchDirectories()
    {
        QStringList directories;
        appendUniquePath(directories, qEnvironmentVariable("KSWORD_ARK_PROFILE_DIR"));
        return directories;
    }

    // loadPdbProfileFile：
    // - 输入 filePath/currentIdentity：候选 JSON 文件和当前 R0 ntoskrnl identity；
    // - 处理：解析 module identity、字段表和 offset 范围；
    // - 返回：LocalPdbProfile；matched=false 表示不是当前内核 profile。
    LocalPdbProfile loadPdbProfileFile(const QString& filePath, const ksword::ark::ArkDynModuleIdentity& currentIdentity)
    {
        LocalPdbProfile profile;
        profile.sourceText = QStringLiteral("scattered-json");
        profile.pathText = QDir::toNativeSeparators(filePath);

        QJsonParseError parseError{};
        QString readErrorText;
        const QJsonDocument document = ks::profile::readProfileJsonDocument(filePath, &parseError, &readErrorText);
        if (parseError.error != QJsonParseError::NoError || !document.isObject())
        {
            profile.diagnosticsText = readErrorText.isEmpty()
                ? kernelText("kernel.dyndata.profile.json_parse_failed", QStringLiteral("JSON 解析失败: %1")).arg(parseError.errorString())
                : readErrorText;
            return profile;
        }

        const QJsonObject rootObject = document.object();
        const QJsonObject moduleObject = rootObject.value(QStringLiteral("module")).toObject();
        std::uint32_t profileClass = 0U;
        std::uint32_t machine = 0U;
        std::uint32_t timeDateStamp = 0U;
        std::uint32_t sizeOfImage = 0U;
        if (!profileClassIdFromText(moduleObject.value(QStringLiteral("class")).toString(), profileClass) ||
            !parseProfileUInt32(moduleObject.value(QStringLiteral("machine")), machine) ||
            !parseProfileUInt32(moduleObject.value(QStringLiteral("timeDateStamp")), timeDateStamp) ||
            !parseProfileUInt32(moduleObject.value(QStringLiteral("sizeOfImage")), sizeOfImage))
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.profile.identity_missing", QStringLiteral("profile module identity 字段缺失或格式无效。"));
            return profile;
        }

        profile.matched = currentIdentity.present &&
            currentIdentity.classId == profileClass &&
            currentIdentity.machine == machine &&
            currentIdentity.timeDateStamp == timeDateStamp &&
            currentIdentity.sizeOfImage == sizeOfImage;
        if (!profile.matched)
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.profile.identity_mismatch", QStringLiteral("profile identity 不匹配当前内核。"));
            return profile;
        }

        const QJsonObject fieldsObject = rootObject.value(QStringLiteral("fields")).toObject();
        profile.applyInput.profileName = rootObject.value(QStringLiteral("profileName")).toString(QFileInfo(filePath).baseName()).toStdString();
        profile.applyInput.pdbName = moduleObject.value(QStringLiteral("pdbName")).toString().toStdString();
        profile.applyInput.pdbGuid = moduleObject.value(QStringLiteral("pdbGuid")).toString().toStdString();
        std::uint32_t pdbAge = 0U;
        if (parseProfileUInt32(moduleObject.value(QStringLiteral("pdbAge")), pdbAge))
        {
            profile.applyInput.pdbAge = pdbAge;
        }
        profile.applyInput.ntoskrnl = currentIdentity;

        std::uint32_t invalidOffsetCount = 0U;
        for (auto iterator = fieldsObject.constBegin(); iterator != fieldsObject.constEnd(); ++iterator)
        {
            std::uint32_t fieldId = 0U;
            std::uint32_t offset = 0U;
            if (!fieldIdForProfileName(iterator.key(), fieldId))
            {
                profile.ignoredUnknownFields += 1U;
                continue;
            }
            if (!parseProfileUInt32(iterator.value(), offset) ||
                offset == 0xFFFFFFFFU ||
                offset > KSW_DYN_PROFILE_OFFSET_MAX)
            {
                invalidOffsetCount += 1U;
                continue;
            }

            ksword::ark::DynDataProfileField field{};
            field.fieldId = fieldId;
            field.offset = offset;
            profile.applyInput.fields.push_back(field);
        }

        QJsonArray typedItemsArray = rootObject.value(QStringLiteral("items")).toArray();
        if (typedItemsArray.isEmpty())
        {
            typedItemsArray = rootObject.value(QStringLiteral("typedItems")).toArray();
        }
        const QJsonArray callbackItemsArray = typedItemsArray.isEmpty()
            ? rootObject.value(QStringLiteral("callbackItems")).toArray()
            : QJsonArray();
        QStringList callbackDiagnostics;
        bool hasCallbackItems = false;
        if (!callbackItemsArray.isEmpty() && !loadCallbackItemsFromJson(callbackItemsArray, profile, callbackDiagnostics, hasCallbackItems))
        {
            profile.diagnosticsText = callbackDiagnostics.join(QStringLiteral(" | "));
            return profile;
        }
        if (hasCallbackItems)
        {
            profile.applyExInput.profileName = profile.applyInput.profileName;
            profile.applyExInput.pdbName = profile.applyInput.pdbName;
            profile.applyExInput.pdbGuid = profile.applyInput.pdbGuid;
            profile.applyExInput.pdbAge = profile.applyInput.pdbAge;
            profile.applyExInput.ntoskrnl = currentIdentity;
        }
        QStringList typedDiagnostics;
        bool hasTypedItems = false;
        if (!loadTypedItemsFromJson(typedItemsArray, profile, typedDiagnostics, hasTypedItems))
        {
            profile.diagnosticsText = typedDiagnostics.join(QStringLiteral(" | "));
            return profile;
        }
        if (hasTypedItems)
        {
            profile.applyExInput.profileName = profile.applyInput.profileName;
            profile.applyExInput.pdbName = profile.applyInput.pdbName;
            profile.applyExInput.pdbGuid = profile.applyInput.pdbGuid;
            profile.applyExInput.pdbAge = profile.applyInput.pdbAge;
            profile.applyExInput.ntoskrnl = currentIdentity;
            profile.applyInput.fields.clear();
        }
        if (fieldsObject.isEmpty() && !hasTypedItems)
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.profile.fields_empty", QStringLiteral("profile fields 为空。"));
            return profile;
        }

        if (invalidOffsetCount != 0U && !hasTypedItems)
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.profile.invalid_offset", QStringLiteral("profile 含 %1 个越界或无效 offset，R3 已拒绝应用。")).arg(invalidOffsetCount);
            return profile;
        }
        if ((profile.applyInput.fields.empty() && profile.applyExInput.items.empty()) ||
            profile.applyInput.fields.size() > KSW_DYN_PROFILE_MAX_FIELDS ||
            profile.applyExInput.items.size() > KSW_DYN_PROFILE_EX_MAX_ITEMS)
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.profile.count_invalid", QStringLiteral("profile 有效字段/item 数量异常: fields=%1 items=%2。"))
                .arg(static_cast<qulonglong>(profile.applyInput.fields.size()))
                .arg(static_cast<qulonglong>(profile.applyExInput.items.size()));
            return profile;
        }

        profile.valid = true;
        profile.diagnosticsText = kernelText("kernel.dyndata.profile.matched_summary", QStringLiteral("profile 匹配，字段 %1 个，typed 项 %2 个，callback 项 %3 个，忽略未知字段 %4 个。"))
            .arg(static_cast<qulonglong>(profile.applyInput.fields.size()))
            .arg(static_cast<qulonglong>(profile.typedItemCount))
            .arg(static_cast<qulonglong>(profile.callbackItemCount))
            .arg(profile.ignoredUnknownFields);
        return profile;
    }

    // loadPdbProfilePackEntry：
    // - 输入 pack 记录/currentIdentity/fieldDictionary/packVersion：pack profile 条目、当前内核身份、字段字典和版本；
    // - 处理：把 v3 typed items 和 v4 stable items 展开为 apply input；
    // - 返回：LocalPdbProfile；matched=false 表示不是当前内核 profile。
    LocalPdbProfile loadPdbProfilePackEntry(
        const QJsonObject& packEntry,
        const QJsonArray& fieldDictionary,
        const std::uint32_t packVersion,
        const ksword::ark::ArkDynModuleIdentity& currentIdentity)
    {
        LocalPdbProfile profile;
        profile.sourceText = QStringLiteral("pack");

        std::uint32_t profileClass = 0U;
        std::uint32_t machine = 0U;
        std::uint32_t timeDateStamp = 0U;
        std::uint32_t sizeOfImage = 0U;
        if (!profileClassIdFromJsonValue(packEntry.value(QStringLiteral("moduleClassId")), profileClass) ||
            !parseProfileUInt32(packEntry.value(QStringLiteral("machine")), machine) ||
            !parseProfileUInt32(packEntry.value(QStringLiteral("timeDateStamp")), timeDateStamp) ||
            !parseProfileUInt32(packEntry.value(QStringLiteral("sizeOfImage")), sizeOfImage))
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.pack.identity_missing", QStringLiteral("pack profile identity 字段缺失或格式无效。"));
            return profile;
        }

        profile.matched = currentIdentity.present &&
            currentIdentity.classId == profileClass &&
            currentIdentity.machine == machine &&
            currentIdentity.timeDateStamp == timeDateStamp &&
            currentIdentity.sizeOfImage == sizeOfImage;
        if (!profile.matched)
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.pack.identity_mismatch", QStringLiteral("pack profile identity 不匹配当前内核。"));
            return profile;
        }

        // Release packs are v4-only.  The old fields/typedItems/legacyItems
        // projections are intentionally ignored even if a stale local file
        // still contains them.
        const QJsonArray fieldsArray;
        const QJsonArray typedItemsArray;
        const QJsonArray v4ItemsArray = packVersion == 4U
            ? packEntry.value(QStringLiteral("items")).toArray()
            : QJsonArray();
        if (fieldsArray.isEmpty() && typedItemsArray.isEmpty() && v4ItemsArray.isEmpty())
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.pack.fields_empty", QStringLiteral("pack profile fields/items 均为空。"));
            return profile;
        }

        const QJsonValue profileNameValue = packEntry.value(QStringLiteral("profileName"));
        const QJsonValue pdbNameValue = packEntry.value(QStringLiteral("pdbName"));
        const QJsonValue pdbGuidValue = packEntry.value(QStringLiteral("pdbGuid"));
        QString profileNameText = profileNameValue.toString().trimmed();
        if (profileNameText.isEmpty())
        {
            profileNameText = QStringLiteral("pack-profile");
        }
        profile.applyInput.profileName = profileNameText.toStdString();
        profile.applyInput.pdbName = pdbNameValue.toString().toStdString();
        profile.applyInput.pdbGuid = pdbGuidValue.toString().toStdString();
        std::uint32_t pdbAge = 0U;
        if (parseProfileUInt32(packEntry.value(QStringLiteral("pdbAge")), pdbAge))
        {
            profile.applyInput.pdbAge = pdbAge;
        }
        profile.applyInput.ntoskrnl = currentIdentity;

        std::uint32_t invalidFieldCount = 0U;
        std::array<bool, KSW_DYN_FIELD_ID_MAX + 1U> seenFieldIds{};
        for (const QJsonValue& entryValue : fieldsArray)
        {
            const QJsonArray pairArray = entryValue.toArray();
            if (pairArray.size() != 2)
            {
                invalidFieldCount += 1U;
                continue;
            }

            std::uint32_t fieldIndex = 0U;
            std::uint32_t offset = 0U;
            if (!parseProfileUInt32(pairArray.at(0), fieldIndex) ||
                !parseProfileUInt32(pairArray.at(1), offset) ||
                fieldIndex >= static_cast<std::uint32_t>(fieldDictionary.size()))
            {
                invalidFieldCount += 1U;
                continue;
            }

            const QString fieldName = fieldDictionary.at(static_cast<int>(fieldIndex)).toString();
            std::uint32_t fieldId = 0U;
            if (!fieldIdForProfileName(fieldName, fieldId))
            {
                profile.ignoredUnknownFields += 1U;
                continue;
            }
            if (offset == 0xFFFFFFFFU || offset > KSW_DYN_PROFILE_OFFSET_MAX)
            {
                invalidFieldCount += 1U;
                continue;
            }
            if (fieldId >= seenFieldIds.size() || seenFieldIds[fieldId])
            {
                invalidFieldCount += 1U;
                continue;
            }
            seenFieldIds[fieldId] = true;

            ksword::ark::DynDataProfileField field{};
            field.fieldId = fieldId;
            field.offset = offset;
            profile.applyInput.fields.push_back(field);
        }

        const QJsonArray callbackItemsArray;
        QStringList callbackDiagnostics;
        bool hasCallbackItems = false;
        if (!callbackItemsArray.isEmpty() && !loadCallbackItemsFromJson(callbackItemsArray, profile, callbackDiagnostics, hasCallbackItems))
        {
            profile.diagnosticsText = callbackDiagnostics.join(QStringLiteral(" | "));
            return profile;
        }
        if (hasCallbackItems)
        {
            profile.applyExInput.profileName = profile.applyInput.profileName;
            profile.applyExInput.pdbName = profile.applyInput.pdbName;
            profile.applyExInput.pdbGuid = profile.applyInput.pdbGuid;
            profile.applyExInput.pdbAge = profile.applyInput.pdbAge;
            profile.applyExInput.ntoskrnl = currentIdentity;
        }

        QStringList typedDiagnostics;
        bool hasTypedItems = false;
        if (!loadTypedItemsFromJson(typedItemsArray, profile, typedDiagnostics, hasTypedItems))
        {
            profile.diagnosticsText = typedDiagnostics.join(QStringLiteral(" | "));
            return profile;
        }
        if (hasTypedItems)
        {
            profile.applyExInput.profileName = profile.applyInput.profileName;
            profile.applyExInput.pdbName = profile.applyInput.pdbName;
            profile.applyExInput.pdbGuid = profile.applyInput.pdbGuid;
            profile.applyExInput.pdbAge = profile.applyInput.pdbAge;
            profile.applyExInput.ntoskrnl = currentIdentity;
            profile.applyInput.fields.clear();
        }
        if (packVersion == 4U)
        {
            QStringList v4Diagnostics;
            if (!loadV4ItemsFromJson(
                    v4ItemsArray,
                    packEntry.value(QStringLiteral("capabilityGroups")).toArray(),
                    currentIdentity,
                    profileNameText,
                    QString::fromStdString(profile.applyInput.pdbName),
                    QString::fromStdString(profile.applyInput.pdbGuid),
                    profile.applyInput.pdbAge,
                    profile,
                    v4Diagnostics))
            {
                profile.diagnosticsText = v4Diagnostics.join(QStringLiteral(" | "));
                return profile;
            }
        }
        if (invalidFieldCount != 0U && v4ItemsArray.isEmpty())
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.pack.invalid_fields", QStringLiteral("pack profile 含 %1 个越界或无效字段，R3 已拒绝应用。"))
                .arg(invalidFieldCount);
            return profile;
        }
        if ((profile.applyInput.fields.empty() && profile.applyExInput.items.empty() && profile.applyV4Input.items.empty()) ||
            profile.applyInput.fields.size() > KSW_DYN_PROFILE_MAX_FIELDS ||
            profile.applyExInput.items.size() > KSW_DYN_PROFILE_EX_MAX_ITEMS)
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.pack.count_invalid", QStringLiteral("pack profile 有效字段/item 数量异常: fields=%1 items=%2。"))
                .arg(static_cast<qulonglong>(profile.applyInput.fields.size()))
                .arg(static_cast<qulonglong>(profile.applyExInput.items.size()));
            return profile;
        }

        profile.valid = true;
        profile.diagnosticsText = kernelText("kernel.dyndata.pack.matched_summary", QStringLiteral("pack profile 匹配，字段 %1 个，typed 项 %2 个，callback 项 %3 个，v4 项 %4 个，忽略未知字段 %5 个。"))
            .arg(static_cast<qulonglong>(profile.applyInput.fields.size()))
            .arg(static_cast<qulonglong>(profile.typedItemCount))
            .arg(static_cast<qulonglong>(profile.callbackItemCount))
            .arg(static_cast<qulonglong>(profile.v4ItemCount))
            .arg(profile.ignoredUnknownFields);
        return profile;
    }

    // loadPdbProfilePackFile：
    // - 输入 filePath/currentIdentity/diagnosticsOut：候选 pack、当前内核身份和诊断输出；
    // - 处理：校验 v4 pack schema 和 profiles 数组，寻找精确匹配条目；
    // - 返回：匹配 profile；未命中或 pack 无效时 valid=false/matched=false。
    LocalPdbProfile loadPdbProfilePackFile(const QString& filePath, const ksword::ark::ArkDynModuleIdentity& currentIdentity, QString& diagnosticsOut)
    {
        LocalPdbProfile bestProfile;
        bestProfile.sourceText = QStringLiteral("pack");
        bestProfile.pathText = QDir::toNativeSeparators(filePath);

        QJsonParseError parseError{};
        QString readErrorText;
        const QJsonDocument document = ks::profile::readProfileJsonDocument(filePath, &parseError, &readErrorText);
        if (parseError.error != QJsonParseError::NoError || !document.isObject())
        {
            diagnosticsOut = readErrorText.isEmpty()
                ? kernelText("kernel.dyndata.pack.json_parse_failed", QStringLiteral("PDB profile pack JSON 解析失败: %1")).arg(parseError.errorString())
                : readErrorText;
            return bestProfile;
        }

        const QJsonObject rootObject = document.object();
        std::uint32_t schemaVersion = 0U;
        std::uint32_t packVersion = 0U;
        if (!parseProfileUInt32(rootObject.value(QStringLiteral("schemaVersion")), schemaVersion) ||
            !parseProfileUInt32(rootObject.value(QStringLiteral("packVersion")), packVersion) ||
            schemaVersion != 1U || packVersion != 4U)
        {
            diagnosticsOut = kernelText("kernel.dyndata.pack.version_unsupported", QStringLiteral("PDB profile pack schemaVersion/packVersion 不支持。"));
            return bestProfile;
        }

        const QJsonArray fieldDictionary = rootObject.value(QStringLiteral("fieldDictionary")).toArray();
        const QJsonArray profilesArray = rootObject.value(QStringLiteral("profiles")).toArray();
        if (!fieldDictionary.isEmpty() || profilesArray.isEmpty())
        {
            diagnosticsOut = kernelText("kernel.dyndata.pack.dictionary_or_profiles_empty", QStringLiteral("PDB profile pack 字段字典或 profile 列表为空。"));
            return bestProfile;
        }

        std::uint32_t invalidDictionaryFields = 0U;
        std::array<bool, KSW_DYN_FIELD_ID_MAX + 1U> seenDictionaryFieldIds{};
        for (const QJsonValue& fieldNameValue : fieldDictionary)
        {
            std::uint32_t ignoredFieldId = 0U;
            if (!fieldNameValue.isString() || !fieldIdForProfileName(fieldNameValue.toString(), ignoredFieldId))
            {
                invalidDictionaryFields += 1U;
                continue;
            }
            if (ignoredFieldId >= seenDictionaryFieldIds.size() || seenDictionaryFieldIds[ignoredFieldId])
            {
                invalidDictionaryFields += 1U;
                continue;
            }
            seenDictionaryFieldIds[ignoredFieldId] = true;
        }
        if (invalidDictionaryFields != 0U)
        {
            diagnosticsOut = kernelText("kernel.dyndata.pack.unknown_dictionary_fields", QStringLiteral("PDB profile pack 字段字典包含 %1 个未知字段，已拒绝。"))
                .arg(invalidDictionaryFields);
            return bestProfile;
        }

        std::uint32_t scannedCount = 0U;
        std::uint32_t invalidMatchedCount = 0U;
        for (const QJsonValue& profileValue : profilesArray)
        {
            if (!profileValue.isObject())
            {
                continue;
            }

            scannedCount += 1U;
            LocalPdbProfile profile = loadPdbProfilePackEntry(profileValue.toObject(), fieldDictionary, packVersion, currentIdentity);
            profile.pathText = QDir::toNativeSeparators(filePath);
            if (profile.matched)
            {
                if (profile.valid)
                {
                    diagnosticsOut = kernelText("kernel.dyndata.pack.matched", QStringLiteral("PDB profile pack 命中；路径=%1，profiles=%2，扫描=%3，%4"))
                        .arg(QDir::toNativeSeparators(filePath))
                        .arg(static_cast<qulonglong>(profilesArray.size()))
                        .arg(scannedCount)
                        .arg(profile.diagnosticsText);
                    return profile;
                }

                invalidMatchedCount += 1U;
                if (!bestProfile.matched)
                {
                    bestProfile = profile;
                    bestProfile.pathText = QDir::toNativeSeparators(filePath);
                }
            }
        }

        diagnosticsOut = kernelText("kernel.dyndata.pack.not_matched", QStringLiteral("PDB profile pack 未命中；路径=%1，profiles=%2，扫描=%3，无效命中=%4。"))
            .arg(QDir::toNativeSeparators(filePath))
            .arg(static_cast<qulonglong>(profilesArray.size()))
            .arg(scannedCount)
            .arg(invalidMatchedCount);
        return bestProfile;
    }

    // findMatchingPdbProfilePack：
    // - 输入 currentIdentity/diagnosticsOut：当前内核身份和诊断输出；
    // - 处理：按默认 pack 路径和环境变量路径查找，返回第一条有效命中；
    // - 返回：匹配 profile；未命中时 valid=false/matched=false。
    LocalPdbProfile findMatchingPdbProfilePack(const ksword::ark::ArkDynModuleIdentity& currentIdentity, QString& diagnosticsOut)
    {
        LocalPdbProfile bestProfile;
        QStringList diagnostics;
        std::uint32_t existingPackCount = 0U;

        for (const QString& packPath : profilePackSearchPaths())
        {
            const QString resolvedPackPath = ks::profile::resolveProfileJsonPath(packPath);
            if (resolvedPackPath.isEmpty())
            {
                diagnostics << kernelText("kernel.dyndata.pack.missing", QStringLiteral("pack 不存在: %1")).arg(QDir::toNativeSeparators(packPath));
                continue;
            }

            existingPackCount += 1U;
            QString packDiagnostics;
            LocalPdbProfile profile = loadPdbProfilePackFile(resolvedPackPath, currentIdentity, packDiagnostics);
            diagnostics << packDiagnostics;
            if (profile.matched)
            {
                if (profile.valid)
                {
                    diagnosticsOut = diagnostics.join(QStringLiteral(" | "));
                    return profile;
                }
                if (!bestProfile.matched)
                {
                    bestProfile = profile;
                }
            }
        }

        diagnosticsOut = kernelText("kernel.dyndata.pack.no_match", QStringLiteral("未找到匹配 PDB profile pack；检查 %1 个存在的 pack。%2"))
            .arg(existingPackCount)
            .arg(diagnostics.join(QStringLiteral(" | ")));
        return bestProfile;
    }

    // findMatchingPdbProfile：
    // - 输入 currentIdentity/diagnosticsOut：当前 ntoskrnl identity 和诊断输出；
    // - 处理：优先扫描 compact pack；仅当 KSWORD_ARK_PROFILE_DIR 显式设置时扫描散落 JSON；
    // - 返回：匹配 profile；未命中时 valid=false/matched=false。
    LocalPdbProfile findMatchingPdbProfileImpl(const ksword::ark::ArkDynModuleIdentity& currentIdentity, QString& diagnosticsOut)
    {
        LocalPdbProfile bestProfile;
        QStringList diagnostics;

        if (!currentIdentity.present)
        {
            diagnosticsOut = kernelText("kernel.dyndata.profile.identity_unavailable", QStringLiteral("当前 ntoskrnl identity 不可用，跳过 PDB profile 扫描。"));
            return bestProfile;
        }

        QString packDiagnostics;
        LocalPdbProfile packProfile = findMatchingPdbProfilePack(currentIdentity, packDiagnostics);
        diagnostics << packDiagnostics;
        if (packProfile.valid)
        {
            diagnosticsOut = packDiagnostics;
            return packProfile;
        }
        if (packProfile.matched)
        {
            return packProfile;
        }

        diagnosticsOut = kernelText("kernel.dyndata.profile.pack_only_no_match", QStringLiteral("未找到匹配的 v4 PDB profile pack。%1"))
            .arg(diagnostics.join(QStringLiteral(" | ")));
        return packProfile;
    }


}

ksword::ark::LocalPdbProfile ksword::ark::findMatchingPdbProfile(
    const ArkDynModuleIdentity& identity, QString& diagnostics,
    const DynDataProfileText& texts)
{
    struct TextScope {
        const ksword::ark::DynDataProfileText* previous = profileTexts;
        explicit TextScope(const ksword::ark::DynDataProfileText* value) { profileTexts = value; }
        ~TextScope() { profileTexts = previous; }
    } scope(&texts);
    return findMatchingPdbProfileImpl(identity, diagnostics);
}
