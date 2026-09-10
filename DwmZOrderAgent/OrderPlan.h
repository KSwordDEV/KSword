#pragma once

#include "../shared/window/DwmZOrderProtocol.h"
#include <cstddef>
#include <cstdint>

namespace ks::dwm_order
{
    // Native Flink order is BACK TO FRONT. ZOrder inserts after its third
    // argument, so that argument is visually BEHIND the target. A null argument
    // means below every sibling (AddVisual(insertAbove=TRUE, reference=NULL)).
    // Zero is the desktop-list sentinel, never a window; Band does not sort it.
    struct OrderPlan
    {
        bool valid = false;
        bool unchanged = false;
        std::uintptr_t behind = 0;
    };

    inline OrderPlan PlanOrder(const std::uintptr_t* windows, std::size_t count,
        std::uintptr_t target, Position position, std::uintptr_t reference)
    {
        if (!windows || !count || !target || count > 8192
            || position > Position::After)
            return {};
        std::size_t targetIndex = count, referenceIndex = count;
        for (std::size_t i = 0; i < count; ++i)
        {
            if (!windows[i]) return {};
            if (windows[i] == target)
            {
                if (targetIndex != count) return {};
                targetIndex = i;
            }
            if (windows[i] == reference)
            {
                if (referenceIndex != count) return {};
                referenceIndex = i;
            }
        }
        if (targetIndex == count) return {};
        if ((position == Position::Before || position == Position::After)
            && (referenceIndex == count || reference == target))
            return {};

        std::uintptr_t behind = 0;
        if (position == Position::Front)
            behind = windows[count - 1] == target
                ? (count > 1 ? windows[count - 2] : 0) : windows[count - 1];
        else if (position == Position::Before)
            behind = reference;
        else if (position == Position::After && referenceIndex)
        {
            behind = windows[referenceIndex - 1];
            if (behind == target)
                behind = referenceIndex > 1 ? windows[referenceIndex - 2] : 0;
        }
        const auto current = targetIndex ? windows[targetIndex - 1] : 0;
        return {true, current == behind, behind};
    }

    struct OrderLocation
    {
        bool valid = false;
        std::uint32_t fromFront = 0;
        std::uintptr_t above = 0;
        std::uintptr_t below = 0;
    };

    inline OrderLocation LocateOrder(const std::uintptr_t* windows, std::size_t count, std::uintptr_t target)
    {
        if (!windows || !count || count > 8192 || !target) return {};
        OrderLocation result;
        for (std::size_t i = 0; i < count; ++i)
        {
            if (!windows[i]) return {};
            if (windows[i] != target) continue;
            if (result.valid) return {};
            result = {true, static_cast<std::uint32_t>(count - i - 1),
                i + 1 < count ? windows[i + 1] : 0, i ? windows[i - 1] : 0};
        }
        return result;
    }
}
