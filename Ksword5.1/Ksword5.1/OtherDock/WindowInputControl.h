#pragma once
#include "WindowInputClient.h"
class QWidget;
namespace ks::window_input
{
    QWidget* CreateControl(const dwm_order::WindowIdentity& identity, QWidget* parent);
    QWidget* CreateInjectionPage(QWidget* parent);
}
