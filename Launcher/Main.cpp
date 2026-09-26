#include "Launcher.h"
#include "../shared/crash/WinCrashHandler.h"

#include <shellapi.h>
#include <sstream>

#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace launcher {

namespace {

std::wstring Text(bool chinese, const wchar_t* zh, const wchar_t* en) { return chinese ? zh : en; }

std::wstring QuoteArgument(const std::wstring& value) {
    if (value.empty()) return L"\"\"";
    bool needsQuotes = false;
    for (wchar_t ch : value) if (iswspace(ch) || ch == L'"') { needsQuotes = true; break; }
    if (!needsQuotes) return value;
    std::wstring output = L"\"";
    unsigned slashCount = 0;
    for (wchar_t ch : value) {
        if (ch == L'\\') { ++slashCount; continue; }
        if (ch == L'"') { output.append(slashCount * 2 + 1, L'\\'); output.push_back(L'"'); slashCount = 0; continue; }
        output.append(slashCount, L'\\'); slashCount = 0; output.push_back(ch);
    }
    output.append(slashCount * 2, L'\\');
    output.push_back(L'"');
    return output;
}

LauncherOptions ParseOptions() {
    LauncherOptions options;
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return options;
    for (int index = 1; index < argc; ++index) {
        const std::wstring argument = argv[index];
        if (argument == L"--launcher-main") { options.targetOverride = true; options.useLight = false; continue; }
        if (argument == L"--launcher-light") { options.targetOverride = true; options.useLight = true; continue; }
        if (argument == L"--launcher-check-only") { options.checkOnly = true; continue; }
        if (argument == L"--launcher-internal-upload") { options.internalUpload = true; continue; }
        if (argument == L"--launcher-internal-marker") { options.internalMarker = true; continue; }
        if (argument == L"--launcher-crash-report") { options.crashReport = true; continue; }
        if (argument == L"--launcher-crash-repeat") { options.crashRepeat = true; continue; }
        if (argument == L"--launcher-crash-pid" && index + 1 < argc) {
            options.crashProcessId = static_cast<DWORD>(wcstoul(argv[++index], nullptr, 0));
            continue;
        }
        if (argument == L"--launcher-crash-code" && index + 1 < argc) {
            options.crashExceptionCode = static_cast<DWORD>(wcstoul(argv[++index], nullptr, 0));
            continue;
        }
        if (argument == L"--launcher-crash-address" && index + 1 < argc) {
            options.crashExceptionAddress = _wcstoui64(argv[++index], nullptr, 0);
            continue;
        }
        if (argument == L"--launcher-crash-dump" && index + 1 < argc) {
            options.crashDumpPath = argv[++index];
            continue;
        }
        if (argument == L"--launcher-crash-dump-written" && index + 1 < argc) {
            options.crashDumpWritten = wcstoul(argv[++index], nullptr, 0) != 0;
            continue;
        }
        if (argument == L"--launcher-crash-ready-event" && index + 1 < argc) {
            options.crashReadyEventName = argv[++index];
            continue;
        }
        if (argument == ks::crash::kCrashRestartedArgument) { continue; }
        if (argument == ks::crash::kCrashRestartWaitPidArgument && index + 1 < argc) {
            ++index;
            continue;
        }
        options.forwardedArguments.push_back(argument);
    }
    LocalFree(argv);
    return options;
}

bool TargetExists(const RuntimePaths& paths, const LauncherOptions& options) {
    return FileExists(options.useLight ? paths.lightPath : paths.mainPath);
}

void ShowTargetMissing(const RuntimePaths& paths, const LauncherOptions& options, bool chinese) {
    const std::wstring target = options.useLight ? paths.lightPath : paths.mainPath;
    ShowSimpleMessage(Text(chinese, L"启动失败", L"Launch failed"),
        Text(chinese, L"找不到启动目标：", L"The launch target was not found: ") + target, chinese);
}

}

bool RelaunchElevated(const LauncherOptions& options, bool forUpload) {
    RuntimePaths paths = ResolveRuntimePaths();
    std::wstring arguments = options.useLight ? L"--launcher-light " : L"--launcher-main ";
    arguments += forUpload ? L"--launcher-internal-upload" : L"--launcher-internal-marker";
    for (const std::wstring& argument : options.forwardedArguments) { arguments.push_back(L' '); arguments += QuoteArgument(argument); }
    const HINSTANCE result = ShellExecuteW(nullptr, L"runas", JoinPath(paths.launcherDirectory, L"Launcher.exe").c_str(), arguments.c_str(), paths.launcherDirectory.c_str(), SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(result) > 32;
}

bool LaunchTarget(const RuntimePaths& paths, const LauncherOptions& options) {
    const std::wstring target = options.useLight ? paths.lightPath : paths.mainPath;
    if (!FileExists(target)) return false;
    std::wstring commandLine = QuoteArgument(target);
    for (const std::wstring& argument : options.forwardedArguments) { commandLine.push_back(L' '); commandLine += QuoteArgument(argument); }
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');
    STARTUPINFOW startup = { sizeof(startup) };
    PROCESS_INFORMATION process = {};
    const BOOL created = CreateProcessW(target.c_str(), mutableCommand.data(), nullptr, nullptr, FALSE, 0, nullptr, paths.launcherDirectory.c_str(), &startup, &process);
    if (!created) return false;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return true;
}

}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    using namespace launcher;
    ks::crash::Configuration crashConfiguration;
    crashConfiguration.productName = L"Ksword Launcher";
    crashConfiguration.dumpFilePrefix = L"Launcher";
    crashConfiguration.preferLauncherReporter = false;
    ks::crash::InstallCrashHandler(crashConfiguration);
    ks::crash::DialogText launcherCrashText;
    if (IsChineseUi()) {
        launcherCrashText.title = L"Ksword Launcher 崩溃";
        launcherCrashText.instruction = L"Ksword Launcher 因未处理的异常停止运行。";
        launcherCrashText.restartQuestion = L"选择“是”重新启动 Launcher，选择“否”退出。";
        launcherCrashText.restartFailedText = L"重新启动 Launcher 失败，程序即将退出。";
    } else {
        launcherCrashText.title = L"Ksword Launcher crashed";
        launcherCrashText.instruction = L"Ksword Launcher stopped because of an unhandled exception.";
        launcherCrashText.restartQuestion = L"Choose Yes to restart Launcher, or No to exit.";
        launcherCrashText.restartFailedText = L"Launcher could not be restarted and will now exit.";
    }
    ks::crash::UpdateCrashDialogText(launcherCrashText);
    (void)ks::crash::WaitForCrashRestartTargetFromCommandLine();
    const bool chinese = IsChineseUi();
    const OsInfo os = QueryOsInfo();
    const RuntimePaths paths = ResolveRuntimePaths();
    LauncherOptions options = ParseOptions();

    if (options.crashReport) {
        return HandleCrashReportMode(paths, options, chinese);
    }

    if (!os.isWindows10OrLater()) {
        ShowUnsupportedOsDialog(os, chinese);
        return 0;
    }

    SupportManifest manifest;
    const bool manifestLoaded = LoadSupportManifest(paths, &manifest);
    if (!manifestLoaded) {
        if (options.checkOnly) {
            ShowSimpleMessage(Text(chinese, L"偏移清单不可用", L"Support manifest unavailable"), Utf8ToWide(manifest.error), chinese);
            return 0;
        }
        if (!options.targetOverride && os.isEarlyQtUnsupported()) {
            const int choice = ShowEarlyWindowsChoiceDialog(chinese);
            if (choice != 1001 && choice != 1002) return 0;
            options.useLight = choice == 1002;
        }
        if (!options.targetOverride && !os.isEarlyQtUnsupported()) options.useLight = false;
        if (!TargetExists(paths, options)) { ShowTargetMissing(paths, options, chinese); return 0; }
        LaunchTarget(paths, options);
        return 0;
    }

    /*
     * Do not let a stale marker or an explicit target override bypass the
     * manifest's build envelope.  The driver also fails closed at R0; this
     * check keeps the normal GUI path from launching an unverified build.
     * Internal upload mode remains available for collecting a support bundle.
     */
    if (manifest.advertisedMaximumBuild != 0UL &&
        os.build > manifest.advertisedMaximumBuild &&
        !manifest.allowNewerWindows11 &&
        !options.internalUpload) {
        ShowUnsupportedBuildDialog(os, manifest.advertisedMaximumBuild, chinese);
        return 0;
    }

    bool markerValid = false;
    if (!options.checkOnly && !options.internalUpload && !options.internalMarker) {
        MarkerState marker;
        if (LoadMarker(paths, &marker)) {
            ScanResult markerScan = ScanCompatibility(manifest);
            if (markerScan.kernel.valid && marker.manifestSha256 == manifest.sha256 && marker.kernelKey == KernelIdentityKey(markerScan.kernel)) {
                if (!options.targetOverride) options.useLight = marker.useLight;
                markerValid = true;
            }
        }
    }

    if (!options.targetOverride && !markerValid && os.isEarlyQtUnsupported()) {
        const int choice = ShowEarlyWindowsChoiceDialog(chinese);
        if (choice != 1001 && choice != 1002) return 0;
        options.useLight = choice == 1002;
    }

    if (markerValid && !options.checkOnly) {
        if (!LaunchTarget(paths, options)) ShowTargetMissing(paths, options, chinese);
        return 0;
    }

    if (!TargetExists(paths, options)) {
        ShowTargetMissing(paths, options, chinese);
        return 0;
    }

    HWND checkingWindow = nullptr;
    ShowCheckingWindow(Text(chinese, L"正在核对偏移清单……", L"Checking the offset support list..."), &checkingWindow);
    ScanResult scan = ScanCompatibility(manifest);
    CloseCheckingWindow(checkingWindow);

    if (options.checkOnly) {
        if (scan.missing.empty()) ShowSimpleMessage(Text(chinese, L"核对完成", L"Check completed"), Text(chinese, L"当前系统的已加载内核模块均有完整偏移信息。", L"All loaded kernel modules have complete offset information."), chinese);
        else ShowSimpleMessage(Text(chinese, L"发现缺少偏移", L"Missing offsets detected"), Text(chinese, L"发现部分已加载内核模块没有完整偏移信息。详细身份已写入上报报告，但检查模式不会启动主程序。", L"Some loaded kernel modules do not have complete offsets. Detailed identities are written to the report only; check-only mode will not launch the program."), chinese);
        return 0;
    }

    if (!scan.missing.empty() && !options.internalUpload && !options.internalMarker) {
        const int choice = ShowMissingDataDialog(chinese);
        if (choice == 1004) {
            if (RelaunchElevated(options, true)) return 0;
            while (ShowUploadElevationFailureDialog(chinese) == 1005) if (RelaunchElevated(options, true)) return 0;
        }
    }

    if (options.internalUpload) {
        std::wstring bundle;
        CollectionProgress progress;
        ShowCollectionProgress(chinese, &progress);
        const bool prepared = PrepareUploadBundle(paths, manifest, scan, &bundle, &progress, chinese);
        CloseCollectionProgress(&progress);
        if (!prepared) {
            ShowSimpleMessage(Text(chinese, L"采集失败", L"Collection failed"),
                Text(chinese, L"无法准备开发者采集文件夹。", L"The developer collection folder could not be prepared."), chinese);
        }
        if (!bundle.empty()) OpenBundleFolder(bundle);
    }

    MarkerState marker;
    marker.manifestSha256 = manifest.sha256;
    marker.kernelKey = KernelIdentityKey(scan.kernel);
    marker.useLight = options.useLight;
    bool accessDenied = false;
    if (!options.internalMarker) {
        if (!WriteMarker(paths, marker, &accessDenied) && accessDenied && RelaunchElevated(options, false)) return 0;
    } else {
        WriteMarker(paths, marker, nullptr);
    }

    if (!LaunchTarget(paths, options)) { ShowTargetMissing(paths, options, chinese); return 0; }
    return 0;
}
