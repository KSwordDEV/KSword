#pragma once
#include "../Common.h"
#include "WindowQueries.h"
namespace ks::r3::window_tools {
bool CopyTextToClipboard(HWND owner, const std::wstring& text);
}
