#pragma once
#include "WindowModel.h"
#include "../../../shared/usermode/backend/window/WindowActions.h"
namespace Ksword::Features::Window {
using ks::r3::window::WindowActionResult;
using ks::r3::window::BringWindowToFront;
using ks::r3::window::MinimizeWindow;
using ks::r3::window::MaximizeWindow;
using ks::r3::window::RestoreWindow;
using ks::r3::window::CloseWindowGracefully;
}
