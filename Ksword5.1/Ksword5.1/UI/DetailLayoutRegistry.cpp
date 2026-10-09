#include "DetailLayoutRegistry.h"

#include "DetailLayoutHost.h"

#include <QList>
#include <QPointer>
#include <QWidget>

namespace
{
    // detailHosts：只保存弱引用；页面销毁后 QPointer 自动变空，下一次调用清理。
    QList<QPointer<ks::ui::DetailLayoutHost>>& detailHosts()
    {
        static QList<QPointer<ks::ui::DetailLayoutHost>> hosts;
        return hosts;
    }

    // currentDetailScheme：进程内唯一全局方案，默认与 AppearanceSettings 保持一致。
    ks::settings::DetailDisplayScheme& currentDetailScheme()
    {
        static ks::settings::DetailDisplayScheme scheme =
            ks::settings::DetailDisplayScheme::BottomCollapsed;
        return scheme;
    }

    // pruneDestroyedHosts：去掉已经随懒加载页面销毁的控制器弱引用。
    void pruneDestroyedHosts()
    {
        QList<QPointer<ks::ui::DetailLayoutHost>>& hosts = detailHosts();
        for (int index = hosts.size() - 1; index >= 0; --index)
        {
            if (hosts.at(index).isNull())
            {
                hosts.removeAt(index);
            }
        }
    }
}

ks::ui::DetailLayoutHost* ks::ui::DetailLayoutRegistry::registerHost(
    QAbstractItemView* tableView,
    CodeEditorWidget* detailEditor,
    QWidget* ownerWidget)
{
    if (tableView == nullptr || detailEditor == nullptr || ownerWidget == nullptr)
    {
        return nullptr;
    }

    pruneDestroyedHosts();
    const auto snapshot = detailHosts();
    for (const QPointer<DetailLayoutHost>& hostPointer : snapshot)
    {
        if (!hostPointer.isNull() && hostPointer->detailEditor() == detailEditor)
        {
            QPointer<DetailLayoutHost> host = hostPointer;
            host->setTableView(tableView);
            if (host.isNull())
            {
                return nullptr;
            }
            host->applyScheme(currentDetailScheme());
            return host.data();
        }
    }

    // 新控制器以页面作为 QObject 父对象，页面卸载时不会留下浮动窗口或回调。
    QPointer<DetailLayoutHost> host = new DetailLayoutHost(tableView, detailEditor, ownerWidget);
    detailHosts().append(host);
    host->applyScheme(currentDetailScheme());
    return host.data();
}

void ks::ui::DetailLayoutRegistry::applyGlobalScheme(
    const ks::settings::DetailDisplayScheme scheme)
{
    currentDetailScheme() = scheme;
    pruneDestroyedHosts();
    const auto snapshot = detailHosts();
    for (const QPointer<DetailLayoutHost>& hostPointer : snapshot)
    {
        if (!hostPointer.isNull())
        {
            hostPointer->applyScheme(scheme);
        }
    }
}

// 新页面直接声明布局，不先调用旧注册入口，避免构造期间先发生祖先推断。
ks::ui::DetailLayoutHost* ks::ui::DetailLayoutRegistry::registerHost(
    QAbstractItemView* tableView,
    CodeEditorWidget* detailEditor,
    QWidget* ownerWidget,
    QSplitter* splitter,
    QWidget* mainPane,
    QWidget* detailPane)
{
    if (tableView == nullptr || detailEditor == nullptr || ownerWidget == nullptr
        || splitter == nullptr || mainPane == nullptr || detailPane == nullptr || mainPane == detailPane)
    {
        return nullptr;
    }
    const DetailPaneBinding binding{splitter, mainPane, detailPane};
    pruneDestroyedHosts();
    const auto snapshot = detailHosts();
    for (const QPointer<DetailLayoutHost>& candidate : snapshot)
    {
        QPointer<DetailLayoutHost> host = candidate;
        if (!host.isNull() && host->detailEditor() == detailEditor)
        {
            if (host->parent() != ownerWidget)
            {
                return nullptr;
            }
            host->setTableView(tableView);
            if (host.isNull())
            {
                return nullptr;
            }
            host->bindPanels(binding);
            if (host.isNull())
            {
                return nullptr;
            }
            host->applyScheme(currentDetailScheme());
            return host.data();
        }
    }
    QPointer<DetailLayoutHost> host = new DetailLayoutHost(tableView, detailEditor, ownerWidget, binding);
    detailHosts().append(host);
    host->applyScheme(currentDetailScheme());
    return host.data();
}

ks::settings::DetailDisplayScheme ks::ui::DetailLayoutRegistry::globalScheme()
{
    return currentDetailScheme();
}

ks::ui::DetailLayoutHost* ks::ui::DetailLayoutRegistry::hostFor(
    CodeEditorWidget* detailEditor)
{
    if (detailEditor == nullptr)
    {
        return nullptr;
    }

    pruneDestroyedHosts();
    const auto snapshot = detailHosts();
    for (const QPointer<DetailLayoutHost>& hostPointer : snapshot)
    {
        if (!hostPointer.isNull() && hostPointer->detailEditor() == detailEditor)
        {
            return hostPointer.data();
        }
    }
    return nullptr;
}

void ks::ui::DetailLayoutRegistry::prepareDataRebuild(CodeEditorWidget* detailEditor)
{
    DetailLayoutHost* host = hostFor(detailEditor);
    if (host != nullptr)
    {
        host->prepareDataRebuild();
    }
}
