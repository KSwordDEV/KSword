#pragma once

#include "NetworkDock.h"
#include "../Internationalization/LanguageManager.h"

#include <QTabWidget>
#include <iterator>

namespace network_navigation_detail
{
    struct Definition
    {
        const char* id;
        const char* parent;
        const wchar_t* sourceTitle;
        const char* binding;
        bool exposed;
    };
    // The actual factories below and the cold catalog consume this one table.
    // Dormant rate-limit/connection factories remain explicitly unexposed.
    inline constexpr Definition Definitions[] = {
        {"traffic", "", L"流量监控", "network.tab.traffic", true},
        {"qos", "", L"QoS 管理", "network.tab.qos", true},
        {"nids", "", L"NIDS", "", true},
        {"rate-limit", "", L"进程限速", "network.tab.rate_limit", false},
        {"connections", "", L"连接管理", "network.tab.connections", false},
        {"connections.tcp", "connections", L"TCP", "", false},
        {"connections.udp", "connections", L"UDP", "", false},
        {"firewall", "", L"防火墙", "network.tab.firewall", true},
        {"firewall.events", "firewall", L"事件监控", "", true},
        {"firewall.rules", "firewall", L"规则管理", "", true},
        {"audit", "", L"网络分析", "network.tab.audit", true},
        {"audit.cross-view", "audit", L"TCP/UDP Cross-View", "", true},
        {"audit.afd", "audit", L"AFD", "", true},
        {"audit.wfp", "audit", L"WFP", "", true},
        {"audit.wfp.provider", "audit.wfp", L"Provider", "", true},
        {"audit.wfp.sublayer", "audit.wfp", L"Sublayer", "", true},
        {"audit.wfp.callout", "audit.wfp", L"Callout", "", true},
        {"audit.wfp.filter", "audit.wfp", L"Filter", "", true},
        {"audit.ndis", "audit", L"NDIS", "", true},
        {"audit.ndis.miniport", "audit.ndis", L"Miniport", "", true},
        {"audit.ndis.binding", "audit.ndis", L"Binding", "", true},
        {"audit.ndis.protocol", "audit.ndis", L"Protocol", "", true},
        {"audit.ndis.unknown", "audit.ndis", L"未知/未证明", "", true},
        {"audit.nsi", "audit", L"NSI", "", true},
        {"port-diagnostics", "", L"端口诊断", "network.tab.port_diagnostics", true},
        {"manual-request", "", L"请求构造", "network.tab.manual_request", true},
        {"download", "", L"多线程下载", "", true},
        {"https", "", L"HTTPS解析", "", true},
        {"route", "", L"路由表", "", true},
        {"arp", "", L"ARP缓存", "", true},
        {"dns", "", L"DNS缓存", "", true},
        {"alive-hosts", "", L"存活主机", "", true},
        {"hosts-editor", "", L"hosts文件编辑", "", true},
    };

    inline const Definition* Find(const QString& id)
    {
        for (const auto& definition : Definitions)
            if (id == QLatin1StringView(definition.id)) return &definition;
        return nullptr;
    }
    inline QString Title(const Definition& definition)
    {
        const QString source = QString::fromWCharArray(definition.sourceTitle);
        auto& language = ks::i18n::LanguageManager::instance();
        return *definition.binding != '\0'
            ? language.text(QString::fromLatin1(definition.binding), source)
            : language.sourceText(source);
    }

    inline int AddTab(QTabWidget* tabs, QWidget* page, const QString& id, const QIcon& icon = {})
    {
        const Definition* definition = Find(id);
        Q_ASSERT(definition != nullptr);
        if (definition == nullptr || tabs == nullptr || page == nullptr) return -1;
        const int existing = tabs->indexOf(page);
        const int index = existing >= 0 ? existing : tabs->addTab(page, icon, Title(*definition));
        if (existing >= 0 && !icon.isNull()) tabs->setTabIcon(index, icon);
        if (existing < 0 && *definition->binding != '\0')
            ks::i18n::LanguageManager::instance().bindTab(tabs, page,
                QString::fromLatin1(definition->binding), QString::fromWCharArray(definition->sourceTitle));
        // Construction-only registration walks a short ancestor chain; providers
        // never discover/scan an existing widget tree or construct a missing page.
        for (QWidget* ancestor = page; ancestor != nullptr; ancestor = ancestor->parentWidget())
        {
            if (auto* dock = qobject_cast<NetworkDock*>(ancestor))
            {
                dock->registerNavigationTab(id, tabs, page);
                break;
            }
        }
        return index;
    }
}
