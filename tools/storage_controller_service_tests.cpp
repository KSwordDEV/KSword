#include "storage_controller_service_stubs.h"
#include "../shared/usermode/KswordArkServiceMode.h"
#include "../Ksword5.1/Ksword5.1/ksword/service/service.h"

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <utility>
#include <vector>

namespace
{
    DWORD registryOpenError = ERROR_SUCCESS;
    DWORD registryQueryError = ERROR_SUCCESS;
    DWORD registryType = REG_DWORD;
    DWORD registryBytes = sizeof(DWORD);
    DWORD registryValue = 1U;
    DWORD currentServiceState = SERVICE_STOPPED;
    unsigned int mutations = 0U;
    unsigned int checks = 0U;
    bool flipProfileOnScmOpen = false;
    bool flipProfileOnStatusQuery = false;
    bool flipProfileAfterStop = false;
    // 捕获 SCM 入口的数据，检查新建与更新是否使用相同的驱动文件路径。
    bool serviceMissing = false;                 // 模拟 SCM 中尚未注册服务。
    std::vector<std::wstring> createImagePaths;   // 新建时实际传入的路径。
    std::vector<std::wstring> changedImagePaths;  // 更新时实际传入的路径。
    void check(const bool value, const char* message)
    {
        ++checks;
        if (!value) throw std::runtime_error(message);
    }
    void setProfile(const DWORD value)
    {
        registryOpenError = ERROR_SUCCESS;
        registryQueryError = ERROR_SUCCESS;
        registryType = REG_DWORD;
        registryBytes = sizeof(DWORD);
        registryValue = value;
    }
    void profileTests()
    {
        using namespace ksword::ark;
        setProfile(1U);
        check(queryServiceProfile().profile == ServiceProfile::StorageControllerPnp,
            "explicit PnP profile must be recognized");
        setProfile(0U);
        check(queryServiceProfile().scmManagementAllowed(), "explicit legacy profile must keep old lifecycle");
        registryOpenError = ERROR_FILE_NOT_FOUND;
        check(queryServiceProfile().scmManagementAllowed(), "absent Parameters defaults to legacy");
        registryOpenError = ERROR_PATH_NOT_FOUND;
        check(queryServiceProfile().scmManagementAllowed(), "absent service path defaults to legacy");
        registryOpenError = ERROR_ACCESS_DENIED;
        check(!queryServiceProfile().scmManagementAllowed(), "unreadable Parameters must fail closed");
        setProfile(0U);
        registryQueryError = ERROR_FILE_NOT_FOUND;
        check(queryServiceProfile().scmManagementAllowed(), "absent profile value defaults to legacy");
        registryQueryError = ERROR_ACCESS_DENIED;
        check(!queryServiceProfile().scmManagementAllowed(), "unreadable profile value must fail closed");
        setProfile(1U);
        registryType = REG_SZ;
        check(!queryServiceProfile().scmManagementAllowed(), "wrong registry type must fail closed");
        setProfile(1U);
        registryBytes = 3U;
        check(!queryServiceProfile().scmManagementAllowed(), "short DWORD must fail closed");
        setProfile(2U);
        check(!queryServiceProfile().scmManagementAllowed(), "unknown profile flag must fail closed");
        check(isKswordArkService(L"kSwOrDaRk") && !isKswordArkService(L"KswordARKController"),
            "name guard must select only the main service case insensitively");
    }
    void serviceTests()
    {
        ks::service::KernelDriverServiceConfig config;
        config.serviceName = L"KswordARK";
        config.binaryPath = L"C:\\app\\KswordARK.sys";
        ks::service::ServiceConfigUpdate update;
        update.changeBinaryPath = true;
        update.binaryPath = config.binaryPath;
        std::string message;
        std::uint32_t error = 0U;
        bool created = false;
        for (unsigned int mode = 0U; mode < 3U; ++mode)
        {
            setProfile(1U);
            if (mode == 1U) registryOpenError = ERROR_ACCESS_DENIED;
            if (mode == 2U) registryType = REG_SZ;
            currentServiceState = SERVICE_STOPPED;
            const unsigned int before = mutations;
            check(!ks::service::StartServiceByName(L"KswordARK", 0U, SERVICE_RUNNING, nullptr, &message, &error),
                "PnP/unknown profile must not be SCM-started without FDO");
            check(!ks::service::StopServiceByName(L"KswordARK", 0U, SERVICE_STOPPED, nullptr, &message, &error),
                "PnP/unknown profile must not be SCM-stopped");
            check(!ks::service::DeleteServiceByName(L"KswordARK", true, 0U, &message, &error),
                "PnP/unknown profile must not be service-deleted");
            check(!ks::service::CreateOrUpdateKernelDriverService(config, &created, &message, &error),
                "PnP/unknown profile must preserve DriverStore ImagePath");
            check(!ks::service::ChangeServiceConfiguration(L"KswordARK", update, &message, &error),
                "PnP/unknown profile must preserve service configuration");
            check(!ks::service::SetServiceDescription(L"KswordARK", L"Changed", &message, &error),
                "PnP/unknown profile must preserve description");
            check(!ks::service::SetDelayedAutoStart(L"KswordARK", true, &message, &error),
                "PnP/unknown profile must preserve delayed auto-start");
            check(!ks::service::ApplyServiceFailureSettings(L"KswordARK", {}, &message, &error),
                "PnP/unknown profile must preserve service recovery settings");
            check(mutations == before, "rejected PnP/unknown operations must call no mutating SCM API");
        }
        setProfile(1U);
        currentServiceState = SERVICE_RUNNING;
        ks::service::ServiceStatus status;
        const unsigned int before = mutations;
        check(ks::service::StartServiceByName(L"KswordARK", 0U, SERVICE_RUNNING, &status, &message, &error) &&
            status.currentState == SERVICE_RUNNING, "running PnP driver must be reused read-only");
        check(mutations == before, "running PnP reuse must not call StartService");
        currentServiceState = SERVICE_START_PENDING;
        check(!ks::service::StartServiceByName(L"KswordARK", 0U, SERVICE_RUNNING, nullptr, &message, &error),
            "PnP pending state must not count as running reuse");

        setProfile(0U);
        currentServiceState = SERVICE_STOPPED;
        check(ks::service::StartServiceByName(L"KswordARK", 0U, SERVICE_RUNNING, nullptr, &message, &error),
            "legacy start must still call SCM");
        check(ks::service::StopServiceByName(L"KswordARK", 0U, SERVICE_STOPPED, nullptr, &message, &error),
            "legacy stop must still call SCM");
        check(ks::service::DeleteServiceByName(L"KswordARK", false, 0U, &message, &error),
            "legacy service deletion must remain available");
        check(ks::service::ChangeServiceConfiguration(L"KswordARK", update, &message, &error),
            "legacy ImagePath update must remain available");
        setProfile(1U);
        check(ks::service::StartServiceByName(L"UnrelatedDriver", 0U, SERVICE_RUNNING, nullptr, &message, &error),
            "other service start must remain unaffected");
        check(ks::service::StopServiceByName(L"UnrelatedDriver", 0U, SERVICE_STOPPED, nullptr, &message, &error),
            "other service stop must remain unaffected");
        check(ks::service::ChangeServiceConfiguration(L"UnrelatedDriver", update, &message, &error),
            "other service configuration must remain unaffected");

        setProfile(0U);
        flipProfileOnScmOpen = true;
        const unsigned int beforeStartRace = mutations;
        check(!ks::service::StartServiceByName(L"KswordARK", 0U, SERVICE_RUNNING, nullptr, &message, &error),
            "start must revalidate after SCM open changes profile");
        check(mutations == beforeStartRace, "start profile race must not mutate SCM");
        flipProfileOnScmOpen = false;
        setProfile(0U);
        currentServiceState = SERVICE_STOPPED;
        flipProfileOnStatusQuery = true;
        const unsigned int beforeDeleteRace = mutations;
        check(!ks::service::DeleteServiceByName(L"KswordARK", false, 0U, &message, &error),
            "delete must revalidate after status query changes profile");
        check(mutations == beforeDeleteRace, "delete profile race must preserve the service");
        flipProfileOnStatusQuery = false;
        setProfile(0U);
        currentServiceState = SERVICE_RUNNING;
        flipProfileAfterStop = true;
        const unsigned int beforeStopRace = mutations;
        check(!ks::service::DeleteServiceByName(L"KswordARK", true, 0U, &message, &error),
            "post-stop profile change must prevent service deletion");
        check(mutations == beforeStopRace + 1U, "post-stop profile race permits only original legacy stop");
        flipProfileAfterStop = false;
    }

    // 对同一组路径分别模拟新建和更新；直接调用生产服务层，不访问真实 SCM。
    void driverImagePathTests()
    {
        const auto cases = { // 输入及其对应的、应传给 SCM 的路径。
            std::pair{L"D:/Perfect Life/D/Driver.sys", L"D:\\Perfect Life\\D\\Driver.sys"},
            std::pair{L"  \"D:/Perfect Life/D/Driver.sys\"  ", L"D:\\Perfect Life\\D\\Driver.sys"},
            std::pair{L"D:/Drivers/Driver.sys", L"D:\\Drivers\\Driver.sys"},
            std::pair{L"\\??\\D:\\Perfect Life\\D\\Driver.sys", L"\\??\\D:\\Perfect Life\\D\\Driver.sys"},
            std::pair{L"\\\\?\\D:\\Perfect Life\\D\\Driver.sys", L"\\\\?\\D:\\Perfect Life\\D\\Driver.sys"},
            std::pair{L"\\SystemRoot\\System32\\drivers\\Driver.sys", L"\\SystemRoot\\System32\\drivers\\Driver.sys"},
            std::pair{L"%SystemRoot%/System32/drivers/Driver.sys", L"%SystemRoot%\\System32\\drivers\\Driver.sys"},
        };
        ks::service::KernelDriverServiceConfig config; // 仅测试普通驱动服务，不改动 KswordARK 配置。
        config.serviceName = L"Issue236Driver";
        for (const auto& [input, expected] : cases) // 测试原始路径与其标准形式。
        {
            config.binaryPath = input;
            for (const bool create : {true, false}) // 分别让模拟 SCM 报告服务缺失或已存在。
            {
                serviceMissing = create;
                createImagePaths.clear();
                changedImagePaths.clear();
                bool created = false; // 接收生产函数报告的新建或更新结果。
                check(ks::service::CreateOrUpdateKernelDriverService(config, &created),
                    "kernel driver registration must succeed");
                check(created == create, "registration must report whether a service was created");
                // 分别核实创建参数和最终更新参数，避免只修复其中一条路径。
                check(createImagePaths.size() == (create ? 1U : 0U), "unexpected CreateServiceW call count");
                if (create)
                {
                    check(createImagePaths.front() == expected, "CreateServiceW received an invalid driver path");
                }
                check(changedImagePaths.size() == 1U && changedImagePaths.front() == expected,
                    "ChangeServiceConfigW received an invalid driver path");
            }
        }

        // 用户态服务的映像字段是命令行，通用更新入口不能移除它的引号或参数。
        ks::service::ServiceConfigUpdate userModeUpdate; // 保存用于对照的用户态服务命令行。
        userModeUpdate.changeBinaryPath = true;
        userModeUpdate.binaryPath = L"\"D:/Program Files/Example.exe\" --service";
        changedImagePaths.clear();
        check(ks::service::ChangeServiceConfiguration(L"Issue236UserMode", userModeUpdate),
            "user-mode service configuration must succeed");
        check(changedImagePaths.size() == 1U && changedImagePaths.front() == userModeUpdate.binaryPath,
            "user-mode service command line must be preserved");
    }
}

LSTATUS WINAPI KsccTestRegOpenKeyExW(HKEY, LPCWSTR path, DWORD, REGSAM access, PHKEY key)
{
    check(std::wcscmp(path, L"SYSTEM\\CurrentControlSet\\Services\\KswordARK\\Parameters") == 0,
        "profile query must address the main service Parameters key");
    check((access & KEY_SET_VALUE) == 0U, "profile query must never request registry write access");
    if (registryOpenError != ERROR_SUCCESS) return registryOpenError;
    *key = reinterpret_cast<HKEY>(static_cast<std::uintptr_t>(1U));
    return ERROR_SUCCESS;
}
LSTATUS WINAPI KsccTestRegQueryValueExW(HKEY, LPCWSTR name, LPDWORD, LPDWORD type, LPBYTE value, LPDWORD bytes)
{
    check(std::wcscmp(name, L"StorageControllerPnP") == 0, "profile query must read explicit PnP flag");
    if (registryQueryError != ERROR_SUCCESS) return registryQueryError;
    *type = registryType;
    std::memcpy(value, &registryValue, sizeof(registryValue));
    *bytes = registryBytes;
    return ERROR_SUCCESS;
}
LSTATUS WINAPI KsccTestRegCloseKey(HKEY) { return ERROR_SUCCESS; }
SC_HANDLE WINAPI KsccTestOpenSCManagerW(LPCWSTR, LPCWSTR, DWORD)
{
    if (flipProfileOnScmOpen) registryValue = 1U;
    return reinterpret_cast<SC_HANDLE>(static_cast<std::uintptr_t>(1U));
}
SC_HANDLE WINAPI KsccTestOpenServiceW(SC_HANDLE, LPCWSTR, DWORD)
{
    // 在新建分支中返回标准错误，其余调用返回模拟句柄。
    if (serviceMissing)
    {
        ::SetLastError(ERROR_SERVICE_DOES_NOT_EXIST);
        return nullptr;
    }
    return reinterpret_cast<SC_HANDLE>(static_cast<std::uintptr_t>(2U));
}
BOOL WINAPI KsccTestCloseServiceHandle(SC_HANDLE) { return TRUE; }
BOOL WINAPI KsccTestQueryServiceStatusEx(SC_HANDLE, SC_STATUS_TYPE, LPBYTE output, DWORD bytes, LPDWORD required)
{
    *required = sizeof(SERVICE_STATUS_PROCESS);
    if (bytes < *required) return FALSE;
    SERVICE_STATUS_PROCESS status{};
    if (flipProfileOnStatusQuery) registryValue = 1U;
    status.dwCurrentState = currentServiceState;
    std::memcpy(output, &status, sizeof(status));
    return TRUE;
}
BOOL WINAPI KsccTestStartServiceW(SC_HANDLE, DWORD, LPCWSTR*)
{ ++mutations; currentServiceState = SERVICE_RUNNING; return TRUE; }
BOOL WINAPI KsccTestControlService(SC_HANDLE, DWORD, LPSERVICE_STATUS)
{
    ++mutations;
    currentServiceState = SERVICE_STOPPED;
    if (flipProfileAfterStop) registryValue = 1U;
    return TRUE;
}
BOOL WINAPI KsccTestDeleteService(SC_HANDLE) { ++mutations; return TRUE; }
// 模拟更新服务；记录传入的二进制路径，返回成功，不写 SCM。
BOOL WINAPI KsccTestChangeServiceConfigW(SC_HANDLE, DWORD, DWORD, DWORD, LPCWSTR imagePath,
    LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR)
{
    ++mutations;
    if (imagePath != nullptr)
    {
        changedImagePaths.emplace_back(imagePath);
    }
    return TRUE;
}
BOOL WINAPI KsccTestChangeServiceConfig2W(SC_HANDLE, DWORD, LPVOID) { ++mutations; return TRUE; }
// 模拟创建服务；保存传入的路径并返回模拟句柄。
SC_HANDLE WINAPI KsccTestCreateServiceW(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD,
    LPCWSTR imagePath, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR)
{
    ++mutations;
    createImagePaths.emplace_back(imagePath);
    return reinterpret_cast<SC_HANDLE>(static_cast<std::uintptr_t>(2U));
}

int main()
{
    try
    {
        profileTests();
        serviceTests();
        driverImagePathTests();
        std::cout << "Storage controller service regression: " << checks << " checks passed\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "FAILED: " << error.what() << '\n';
        return 1;
    }
}
