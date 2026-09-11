#pragma once
#include <cstdint>
class QWidget;
class QString;
namespace ks::dwm_order
{
    struct Reply;
    struct WindowIdentity;
    QWidget* CreateControl(const WindowIdentity& identity, QWidget* parent);
    QString ErrorDescription(const Reply& reply);
}
