#include "PointerText.h"

namespace ks::r3::window_tools {
std::wstring PointerText(const std::uint64_t value) {
    return HexText(value, 16);
}
}
