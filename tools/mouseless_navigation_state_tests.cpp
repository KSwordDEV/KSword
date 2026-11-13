#include "../Ksword5.1/Ksword5.1/UI/MouselessNavigationState.h"
#include <cstdlib>
#include <iostream>

using Gesture = ks::ui::MouselessGesture;
using Key = Gesture::Key;
static int checks = 0;
static void require(bool condition, const char* description)
{
    ++checks;
    if (!condition) { std::cerr << "FAIL: " << description << '\n'; std::exit(1); }
}

int main()
{
    for (const auto alt : {Key::LeftAlt, Key::RightAlt})
    {
        Gesture g;
        require(!g.update(Key::Control, true, true, false, 0), "Ctrl alone");
        require(!g.update(alt, true, true, false, 10), "first press");
        require(!g.update(alt, true, true, true, 20), "repeat is not a second tap");
        require(!g.update(alt, false, true, false, 40), "first release");
        require(g.update(alt, true, true, false, 140), "double tap enters");
        require(!g.update(alt, true, true, true, 150), "held toggle does not repeat");
        require(!g.update(alt, false, true, false, 170), "toggle release");
        require(!g.update(alt, true, true, false, 200), "third tap does not toggle again");
        require(!g.update(alt, false, true, false, 220), "third release");
        require(g.update(alt, true, true, false, 250), "next double tap exits");
    }
    for (const auto first : {Key::LeftAlt, Key::RightAlt})
    {
        const auto second = first == Key::LeftAlt ? Key::RightAlt : Key::LeftAlt;
        Gesture g;
        require(!g.update(first, true, true, false, 0), "one Alt is not a chord");
        require(g.update(second, true, true, false, 50), "both physical Alt keys toggle");
        require(!g.update(second, true, true, true, 60), "chord repeat ignored");
        require(!g.update(first, false, true, false, 70), "chord partly released");
        require(!g.update(first, true, true, false, 80), "partly held chord not retriggered");
        require(!g.update(second, false, true, false, 90), "release right");
        require(!g.update(first, false, true, false, 100), "release left");
        require(!g.update(first, true, true, false, 150), "new chord first Alt");
        require(g.update(second, true, true, false, 160), "new chord toggles");
    }
    {
        Gesture g;
        require(!g.update(Key::LeftAlt, true, false, false, 0), "Alt without Ctrl");
        require(!g.update(Key::RightAlt, true, false, false, 10), "both Alt without Ctrl");
        require(g.update(Key::Control, true, true, false, 20), "Ctrl pressed last also works");
    }
    for (int scenario = 0; scenario < 7; ++scenario)
    {
        Gesture g;
        g.update(Key::LeftAlt, true, true, false, 0);
        if (scenario == 1) g.update(Key::Other, true, true, false, 10); // Ctrl+Alt+S / AltGr text
        g.update(Key::LeftAlt, false, true, false, scenario == 2 ? 501 : 40);
        if (scenario == 3) g.update(Key::Control, false, false, false, 50);
        if (scenario == 4) g.reset(); // Alt+Tab / losing app activation
        if (scenario == 5) g.update(Key::Other, true, true, false, 70);
        const auto time = scenario == 0 ? 741 : 700;
        const bool actual = g.update(Key::LeftAlt, true, scenario != 6, false, time);
        require(!actual, "slow/interrupted/unmodified taps must not toggle");
    }
    {
        Gesture g;
        g.update(Key::RightAlt, true, true, false, 0);
        g.update(Key::Other, true, true, false, 20);
        g.update(Key::RightAlt, false, true, false, 40);
        require(!g.update(Key::RightAlt, true, true, false, 60), "AltGr typing is not a tap pair");
    }
    require(ks::ui::MouselessNextIndex(-1, 0, false) == -1, "empty window");
    require(ks::ui::MouselessNextIndex(-1, 3, false) == 0, "recover missing focus");
    require(ks::ui::MouselessNextIndex(-1, 3, true) == 2, "reverse from missing focus");
    require(ks::ui::MouselessNextIndex(8, 3, false) == 0, "destroyed region");
    require(ks::ui::MouselessNextIndex(2, 3, false) == 0, "forward wraps");
    require(ks::ui::MouselessNextIndex(0, 3, true) == 2, "reverse wraps");
    require(ks::ui::MouselessNextIndex(0, 1, false) == 0, "single region remains usable");
    for (int count = 1; count <= 40; ++count)
    {
        int cursor = 0;
        for (int i = 0; i < count; ++i) cursor = ks::ui::MouselessNextIndex(cursor, count, false);
        require(cursor == 0, "forward cycle returns exactly once");
        for (int i = 0; i < count; ++i) cursor = ks::ui::MouselessNextIndex(cursor, count, true);
        require(cursor == 0, "reverse cycle returns exactly once");
    }
    std::cout << "MOUSELESS_STATE_CHECKS=" << checks << " PASS (no widgets or input injection)\n";
}
