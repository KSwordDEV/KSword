// External services are replaced for an isolated Qt snapshot host. The shared
// editor, decoder, assembler, row canvases and history remain production code.
#include "Ksword5.1/Ksword5.1/UI/UI_All.h"
#include "Ksword5.1/Ksword5.1/UI/X64DbgNavigation.h"
#include "Ksword5.1/Ksword5.1/UI/HvmWatchDialog.h"
#include "Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "Ksword5.1/Ksword5.1/PluginHost.h"
#include <QMenu>

namespace fixture
{
    QString lastManagedPlugin;
}

namespace ks::plugin_host
{
    void showPluginManager(QWidget*, const QString& pluginId)
    {
        fixture::lastManagedPlugin = pluginId;
    }
}

namespace ks::ui
{
    void applyResponsiveWindowGeometry(QWidget* window, QWidget*, const QSize& size,
        const QSize& minimum, double)
    {
        window->setMinimumSize(minimum);
        window->resize(size);
    }
    void openHvmWatch(QWidget*, const HvmWatchRequest&) {}
}

namespace ks::ui::x64dbg_navigation
{
    quint64 ProcessCreateTime100ns(quint32) noexcept { return 0; }
    void AddAction(QMenu* menu, QWidget*, const Target&)
    {
        // Observe that the production host supplies a navigation target, while
        // keeping every action disconnected from external processes.
        menu->addAction(QStringLiteral("x64dbg fixture"));
    }
}

namespace ksword::ark
{
    VirtualMemoryReadResult DriverClient::readVirtualMemory(std::uint32_t,
        std::uint64_t, std::uint32_t, unsigned long, DriverHandle*) const { return {}; }
    MutationResponseResult DriverClient::prepareMutation(const MutationPrepareInput&) const { return {}; }
    MutationResponseResult DriverClient::commitMutation(std::uint64_t, unsigned long) const { return {}; }
    MutationResponseResult DriverClient::rollbackMutation(std::uint64_t, unsigned long) const { return {}; }
}
