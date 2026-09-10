#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include "../OrderPlan.h"
#include <algorithm>
#include <initializer_list>
#include <iostream>
#include <cwchar>
#include <vector>

using namespace ks::dwm_order;
void RunLoaderTests(void (*check)(bool, const char*), const wchar_t* agentPath);
void RunCfgTests(void (*check)(bool, const char*));
int RunCfgRepro(const wchar_t* fixture);
namespace
{
    int failures = 0;
    unsigned checks = 0;
    void Check(bool value, const char* description)
    {
        ++checks;
        if (!value) { ++failures; std::cerr << "FAIL: " << description << '\n'; }
    }

    // Independent opaque-pixel oracle: DirectComposition paints native Flink
    // order back-to-front, so the last covering visual determines the pixel.
    std::uintptr_t PaintedWindow(const std::vector<std::uintptr_t>& windows,
        std::uintptr_t first = 0, std::uintptr_t second = 0)
    {
        std::uintptr_t pixel = 0;
        for (const auto window : windows)
            if (!first || window == first || window == second) pixel = window;
        return pixel;
    }

    void Order(std::initializer_list<std::uintptr_t> input, std::uintptr_t target,
        Position position, std::uintptr_t reference, std::initializer_list<std::uintptr_t> expected)
    {
        std::vector<std::uintptr_t> windows(input);
        const auto plan = PlanOrder(windows.data(), windows.size(), target, position, reference);
        Check(plan.valid, "valid ordering request");
        if (!plan.valid) return;
        if (!plan.unchanged)
        {
            windows.erase(std::find(windows.begin(), windows.end(), target));
            auto at = windows.begin();
            if (plan.behind) at = std::find(windows.begin(), windows.end(), plan.behind) + 1;
            windows.insert(at, target);
        }
        Check(windows == std::vector<std::uintptr_t>(expected), "expected compositor order");
        const auto repeat = PlanOrder(windows.data(), windows.size(), target, position, reference);
        Check(repeat.valid && repeat.unchanged, "reapplying an order is idempotent");
        std::vector<std::uintptr_t> othersBefore(input), othersAfter(windows);
        othersBefore.erase(std::find(othersBefore.begin(), othersBefore.end(), target));
        othersAfter.erase(std::find(othersAfter.begin(), othersAfter.end(), target));
        Check(othersBefore == othersAfter, "unselected windows retain their relative order");
        if (position == Position::Front)
            Check(PaintedWindow(windows) == target, "move-to-front target covers every overlapping sibling");
        else if (position == Position::Back)
            Check(windows.size() == 1 || PaintedWindow(windows) != target,
                "send-to-back target is covered by its overlapping siblings");
        else
            Check(PaintedWindow(windows, target, reference) == (position == Position::Before ? target : reference),
                "relative visual occlusion agrees with before/after, not raw list direction");
    }
}

int RunRuntimeTests(int argc, wchar_t** argv);

int wmain(int argc, wchar_t** argv)
{
    if (argc >= 3 && std::wcscmp(argv[1], L"--runtime") == 0)
        return RunRuntimeTests(argc - 2, argv + 2);

    if (argc == 3 && lstrcmpW(argv[1], L"--cfg-repro") == 0) return RunCfgRepro(argv[2]);
    if (argc == 4 && lstrcmpW(argv[1], L"--loader-child") == 0)
    {
        HANDLE finished = reinterpret_cast<HANDLE>(_wcstoui64(argv[2], nullptr, 10));
        HANDLE ready = reinterpret_cast<HANDLE>(_wcstoui64(argv[3], nullptr, 10));
        SetEvent(ready);
        const DWORD wait = WaitForSingleObject(finished, 60000);
        CloseHandle(ready);
        CloseHandle(finished);
        return wait == WAIT_OBJECT_0 ? 0 : 1;
    }
    // Each array is the native list: lowest visual first, highest visual last.
    Order({1,2,3,4}, 3, Position::Front, 0, {1,2,4,3});
    Order({1,2,3,4}, 4, Position::Back, 0, {4,1,2,3});
    Order({1,2,3,4}, 4, Position::Front, 0, {1,2,3,4});
    Order({1,2,3,4}, 1, Position::Back, 0, {1,2,3,4});
    Order({1}, 1, Position::Front, 0, {1});
    Order({1}, 1, Position::Back, 0, {1});
    Order({1,2,3,4}, 4, Position::Before, 1, {1,4,2,3});
    Order({1,2,3,4}, 1, Position::Before, 4, {2,3,4,1});
    Order({1,2,3,4}, 2, Position::Before, 3, {1,3,2,4});
    Order({1,2,3,4}, 1, Position::Before, 2, {2,1,3,4});
    Order({1,2,3,4}, 1, Position::After, 4, {2,3,1,4});
    Order({1,2,3,4}, 4, Position::After, 1, {4,1,2,3});
    Order({1,2,3,4}, 3, Position::After, 2, {1,3,2,4});
    Order({1,2,3,4}, 2, Position::Before, 1, {1,2,3,4});
    Order({1,2,3,4}, 1, Position::After, 2, {1,2,3,4});
    // IDs intentionally do not encode Band priority: any node may cross another.
    Order({1,18,200}, 1, Position::Front, 0, {18,200,1});
    Order({200,18,1}, 1, Position::Back, 0, {1,200,18});
    const std::uintptr_t windows[] = {1,2,3};
    const auto front = LocateOrder(windows, 3, 3);
    const auto middle = LocateOrder(windows, 3, 2);
    const auto back = LocateOrder(windows, 3, 1);
    Check(front.valid && front.fromFront == 0 && front.above == 0 && front.below == 2,
        "frontmost receipt has index zero and no window above it");
    Check(middle.valid && middle.fromFront == 1 && middle.above == 3 && middle.below == 1,
        "receipt neighbors describe visual above/below");
    Check(back.valid && back.fromFront == 2 && back.above == 2 && back.below == 0,
        "backmost receipt reverses native list indexing");
    Check(!LocateOrder(windows, 3, 4).valid, "missing target has no valid receipt position");
    // Restoring target 3 in Win32 order [4,3,2,1] uses its lower neighbor 2.
    Order({1,2,4,3}, 3, Position::Before, 2, {1,2,3,4});
    Check(!PlanOrder(windows,3,4,Position::Front,0).valid, "closed target is rejected");
    Check(!PlanOrder(windows,3,1,Position::After,4).valid, "closed reference is rejected");
    Check(!PlanOrder(windows,3,1,Position::Before,1).valid, "self reference is rejected");
    Check(!PlanOrder(windows,3,1,static_cast<Position>(99),0).valid, "invalid position is rejected");
    Check(!PlanOrder(nullptr,0,1,Position::Front,0).valid, "empty list is rejected");
    const std::uintptr_t duplicate[] = {1,2,1};
    const std::uintptr_t sentinel[] = {1,0,2};
    Check(!PlanOrder(duplicate,3,1,Position::Front,0).valid, "duplicate target is rejected");
    Check(!PlanOrder(sentinel,3,1,Position::Front,0).valid, "sentinel cannot be a window");

    Check(argc == 2, "agent DLL path supplied");
    if (argc == 2)
    {
        RunLoaderTests(&Check, argv[1]);
        RunCfgTests(&Check);
        HMODULE agent = LoadLibraryW(argv[1]);
        Check(agent != nullptr, "agent DLL loads in the ordinary test process");
        if (agent)
        {
            auto entry = reinterpret_cast<DWORD(WINAPI*)(void*)>(GetProcAddress(agent, "KswordDwmZOrderRequest"));
            Check(entry != nullptr, "request export has the expected ABI name");
            if (entry)
            {
                Check(entry(nullptr) == ERROR_INVALID_PARAMETER, "null request is rejected");
                Packet packet;
                packet.version = 999;
                Check(entry(&packet) == ERROR_SUCCESS && packet.response.status == Status::InvalidRequest,
                    "unknown protocol is rejected before runtime initialization");
                packet = {};
                packet.version = 1;
                packet.bytes = 144;
                Check(entry(&packet) == ERROR_SUCCESS && packet.response.status == Status::InvalidRequest,
                    "old protocol without query-only process handles is rejected");
                packet = {};
                Check(entry(&packet) == ERROR_SUCCESS && packet.response.status == Status::UnsupportedRuntime,
                    "agent refuses to modify a process other than DWM");
            }
            FreeLibrary(agent);
        }
    }
    std::cout << "CHECKS=" << checks << " FAILURES=" << failures << '\n';
    return failures ? 1 : 0;
}
