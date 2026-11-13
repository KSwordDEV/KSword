#pragma once

#include <cstdint>

namespace ks::ui
{
    // Pure input state: no global hotkey, polling, or dependency on a widget's focus.
    class MouselessGesture final
    {
    public:
        enum class Key { Control, LeftAlt, RightAlt, Other };

        bool update(Key key, bool down, bool controlDown, bool repeat, std::int64_t now)
        {
            const unsigned bit = key == Key::LeftAlt ? 1u : key == Key::RightAlt ? 2u : 0u;
            // Windows can report generic VK_MENU as already down when the other
            // physical Alt key is newly pressed. Only a repeat of the same side is ignored.
            if (repeat && (bit == 0 || !down || (m_alts & bit) != 0)) return false;
            if (bit != 0)
            {
                if (down) m_alts |= bit;
                else m_alts &= ~bit;
            }
            if (!controlDown)
            {
                m_armed = false;
                m_latched = false;
                m_pressedAt = -1;
                return false;
            }
            if (down && key == Key::Other)
            {
                m_armed = false;
                m_pressedAt = -1; // Ctrl+Alt+letter is not an Alt tap.
                return false;
            }
            if (m_alts == 3 && !m_latched)
            {
                m_latched = true;
                m_armed = false;
                m_pressedAt = -1;
                return true;
            }
            if (bit != 0 && down && !m_latched)
            {
                if (m_armed && now >= m_releasedAt && now - m_releasedAt <= 700)
                {
                    m_latched = true;
                    m_armed = false;
                    m_pressedAt = -1;
                    return true;
                }
                m_armed = false;
                m_pressedAt = now;
            }
            else if (bit != 0 && !down && m_alts == 0)
            {
                m_armed = !m_latched && m_pressedAt >= 0 && now >= m_pressedAt
                    && now - m_pressedAt <= 500;
                m_releasedAt = now;
                m_pressedAt = -1;
                m_latched = false;
            }
            return false;
        }

        void reset() { *this = {}; }

    private:
        unsigned m_alts = 0;
        bool m_armed = false;
        bool m_latched = false;
        std::int64_t m_pressedAt = -1;
        std::int64_t m_releasedAt = 0;
    };

    // Empty/one-region windows and a destroyed previous target still have a defined route.
    inline int MouselessNextIndex(int current, int count, bool backwards)
    {
        if (count <= 0) return -1;
        if (current < 0 || current >= count) return backwards ? count - 1 : 0;
        return (current + (backwards ? count - 1 : 1)) % count;
    }
}
