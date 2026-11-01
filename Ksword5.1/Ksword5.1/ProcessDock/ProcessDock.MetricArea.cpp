#include "ProcessDock.h"
#include "../UI/MetricAreaWindow.h"
#include "../Internationalization/LanguageManager.h"
#include <QDateTime>
#include <QBrush>
#include <QItemSelectionModel>
#include <QTableView>
#include <QTimer>
#include <cmath>

namespace { QString areaText(const char* text){return ks::i18n::sourceText(QString::fromUtf8(text));} }

struct ProcessDock::MetricAreaSnapshot {
    struct Entry { ProcessTableRow row; int parent = -1; QString key; bool group = false; };
    std::vector<Entry> entries;
    QString time;
    bool historical = false, friendly = false, tree = false;
};

bool ProcessDock::isMetricAreaColumn(const int column){
    if(column<0||column>=static_cast<int>(TableColumn::Count)||column==static_cast<int>(TableColumn::Ram))return false;
    if(column==static_cast<int>(TableColumn::CpuCore))return true;
    // Reuse the semantic resource/counter whitelist, independently of per-row availability.
    ks::process::ProcessRecord probe;probe.cycleTimeKnown=probe.memoryDetailKnown=probe.privateWorkingSetKnown=true;
    probe.guiResourceKnown=probe.ioDetailKnown=probe.gpuMemoryKnown=true;
    double value=0;return processUsageHighlightValue(probe,static_cast<TableColumn>(column),&value);
}

bool ProcessDock::metricAreaIncludesProcess(const int column, const ks::process::ProcessRecord& record){
    if(column!=static_cast<int>(TableColumn::Cpu)&&column!=static_cast<int>(TableColumn::CpuCore))return true;
    return record.pid!=0U&&QString::fromStdString(record.processName).compare(
        QStringLiteral("System Idle Process"),Qt::CaseInsensitive)!=0;
}

void ProcessDock::openMetricAreaWindow(const int column){
    if(!isMetricAreaColumn(column))return;
    if(auto window=m_metricAreaWindows.value(column)){window->show();window->raise();window->activateWindow();return;}
    auto* window=new ks::ui::MetricAreaWindow(this);m_metricAreaWindows.insert(column,window);
    const QPointer<ProcessDock> guard(this);
    connect(window,&QObject::destroyed,this,[guard,column](){if(guard){guard->m_metricAreaWindows.remove(column);if(guard->m_metricAreaWindows.isEmpty())guard->m_metricAreaSnapshot.reset();}});
    window->appearanceChanged=[guard](){if(guard)guard->scheduleMetricAreaRefresh();};
    // Opening the first view commits the same cached data to the main table and area view together.
    rebuildTable();window->show();window->raise();window->activateWindow();
}

void ProcessDock::scheduleMetricAreaRefresh(){
    if(m_metricAreaWindows.isEmpty()||m_metricAreaRefreshScheduled)return;
    m_metricAreaRefreshScheduled=true;
    QTimer::singleShot(0,this,[this](){m_metricAreaRefreshScheduled=false;refreshMetricAreaViews(false);});
}

void ProcessDock::updateMetricAreaState(){
    if(!m_metricAreaSnapshot)return;
    const auto& snapshot=*m_metricAreaSnapshot;
    const QString mode=snapshot.friendly?areaText("友好视图"):snapshot.tree?areaText("进程树"):areaText("扁平列表");
    const QString state=snapshot.historical?areaText("历史快照"):m_monitoringEnabled?areaText("跟随主列表"):areaText("已暂停");
    for(auto it=m_metricAreaWindows.cbegin();it!=m_metricAreaWindows.cend();++it){
        if(!it.value())continue;
        QString text=state+QStringLiteral(" · ")+snapshot.time+QStringLiteral(" · ")+mode;
        if(it.key()==static_cast<int>(TableColumn::WorkingSetDelta)||it.key()==static_cast<int>(TableColumn::PageFaultDelta))
            text+=QStringLiteral(" · ")+areaText("面积按变化绝对值计算，正负方向保留在数值中。");
        if(snapshot.friendly)text+=QStringLiteral(" · ")+areaText("包含折叠分组内的进程。");
        it.value()->updateState(std::move(text));
    }
}

void ProcessDock::refreshMetricAreaViews(const bool captureRows){
    if(m_metricAreaWindows.isEmpty())return;
    if(captureRows){
        auto snapshot=std::make_shared<MetricAreaSnapshot>();
        snapshot->historical=isProcessActivityTableSnapshotActive();
        snapshot->friendly=isFriendlyViewEnabled()&&currentProcessSearchText().isEmpty();
        snapshot->tree=isTreeModeEnabled()&&currentProcessSearchText().isEmpty();
        snapshot->time=QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
        auto source=buildProcessTreeDisplayOrder(buildListDisplayOrder(),snapshot->historical);
        std::vector<int> ancestors;
        snapshot->entries.reserve(source.size()+8);
        for(const auto& display:source){
            MetricAreaSnapshot::Entry entry;
            entry.row.record=*display.record;entry.row.identityKey=ks::process::BuildProcessIdentityKey(display.record->pid,display.record->creationTime100ns);
            entry.row.isNew=display.isNew;entry.row.isExited=display.isExited;entry.row.isKernelOnly=display.isKernelOnly;
            entry.row.activitySnapshotActive=snapshot->historical;entry.key=QString::fromStdString(entry.row.identityKey);
            if(snapshot->historical)snapshot->time=QString::fromStdString(display.record->startTimeText);
            if(snapshot->tree||snapshot->friendly){
                while(static_cast<int>(ancestors.size())>display.depth)ancestors.pop_back();
                entry.parent=ancestors.empty()?-1:ancestors.back();
                ancestors.push_back(static_cast<int>(snapshot->entries.size()));
            }
            snapshot->entries.push_back(std::move(entry));
        }
        if(snapshot->friendly){
            const int processCount=static_cast<int>(snapshot->entries.size());
            const auto addGroup=[&](QString key,QString title,int parent){
                MetricAreaSnapshot::Entry entry;entry.key=std::move(key);entry.row.record.processName=title.toStdString();entry.group=true;entry.parent=parent;
                snapshot->entries.push_back(std::move(entry));return static_cast<int>(snapshot->entries.size()-1);
            };
            const int groups[3]={addGroup(QStringLiteral("area:applications"),friendlyGroupTypeName(FriendlyProcessGroupType::Application),-1),
                addGroup(QStringLiteral("area:background"),friendlyGroupTypeName(FriendlyProcessGroupType::Background),-1),
                addGroup(QStringLiteral("area:system"),friendlyGroupTypeName(FriendlyProcessGroupType::WindowsSystem),-1)};
            std::unordered_map<std::uint32_t,int> applications;
            std::unordered_map<std::uint32_t,QString> names;
            for(int i=0;i<processCount;++i)names[snapshot->entries[i].row.record.pid]=QString::fromStdString(snapshot->entries[i].row.record.processName);
            for(int i=0;i<processCount;++i){
                const auto& identity=snapshot->entries[i].row.identityKey;
                const auto group=m_metricFriendlyGroups.find(identity);
                const auto type=group==m_metricFriendlyGroups.end()?FriendlyProcessGroupType::Background:group->second;
                const auto root=m_metricFriendlyRoots.find(identity);
                if(type==FriendlyProcessGroupType::Application&&root!=m_metricFriendlyRoots.end()&&applications.find(root->second)==applications.end())
                    applications[root->second]=addGroup(QStringLiteral("area:app:")+QString::number(root->second),names[root->second],groups[0]);
            }
            for(int i=0;i<processCount;++i){
                auto& entry=snapshot->entries[i];const auto group=m_metricFriendlyGroups.find(entry.row.identityKey);
                const auto type=group==m_metricFriendlyGroups.end()?FriendlyProcessGroupType::Background:group->second;entry.row.friendlyGroupType=type;
                if(type!=FriendlyProcessGroupType::Application){entry.parent=groups[static_cast<int>(type)];continue;}
                const auto root=m_metricFriendlyRoots.find(entry.row.identityKey);
                if(root==m_metricFriendlyRoots.end()){entry.parent=groups[0];continue;}
                const auto parentRoot=entry.parent>=0?m_metricFriendlyRoots.find(snapshot->entries[entry.parent].row.identityKey):m_metricFriendlyRoots.end();
                if(parentRoot==m_metricFriendlyRoots.end()||parentRoot->second!=root->second)entry.parent=applications[root->second];
            }
        }
        m_metricAreaSnapshot=std::move(snapshot);
    }
    const auto snapshot=m_metricAreaSnapshot;if(!snapshot)return;
    for(auto it=m_metricAreaWindows.cbegin();it!=m_metricAreaWindows.cend();++it){
        auto window=it.value();if(!window)continue;const int column=it.key();const auto metric=static_cast<TableColumn>(column);
        std::vector<ks::ui::MetricAreaNode> nodes;nodes.reserve(snapshot->entries.size());
        std::vector<int> projectionIndexes(snapshot->entries.size(),-1);
        double total=0;
        for(std::size_t sourceIndex=0;sourceIndex<snapshot->entries.size();++sourceIndex){
            const auto& entry=snapshot->entries[sourceIndex];
            if(!entry.group&&!metricAreaIncludesProcess(column,entry.row.record))continue;
            ks::ui::MetricAreaNode node;node.key=entry.key;node.parent=entry.parent;node.group=entry.group;
            node.name=QString::fromStdString(entry.row.record.processName);
            if(!entry.group){
                node.pid=QString::number(entry.row.record.pid);node.icon=resolveProcessIcon(entry.row.record);
                double weight=0;node.known=metric==TableColumn::CpuCore||processUsageHighlightValue(entry.row.record,metric,&weight);
                if(metric==TableColumn::CpuCore)weight=std::fabs(entry.row.record.cpuCorePercent);
                node.weight=node.known&&std::isfinite(weight)?weight:0;total+=node.weight;
                node.value=processTableData(entry.row,column,Qt::DisplayRole).toString();
                const auto background=processTableData(entry.row,column,Qt::BackgroundRole);
                if(background.isValid())node.background=background.value<QBrush>().color();
                const auto foreground=processTableData(entry.row,column,Qt::ForegroundRole);
                if(foreground.isValid())node.foreground=foreground.value<QBrush>().color();
                node.tooltip=ks::i18n::sourceText(QStringLiteral("%1 · PID %2\n%3: %4\nPPID %5\n%6\n%7")).arg(node.name,node.pid,
                    processColumnDisplayName(column),node.value).arg(entry.row.record.parentPid)
                    .arg(QString::fromStdString(entry.row.record.imagePath),snapshot->time);
            }
            projectionIndexes[sourceIndex]=static_cast<int>(nodes.size());nodes.push_back(std::move(node));
        }
        for(auto& node:nodes){
            int parent=node.parent;
            while(parent>=0&&projectionIndexes[parent]<0)parent=snapshot->entries[parent].parent;
            node.parent=parent>=0?projectionIndexes[parent]:-1;
        }
        for(auto& node:nodes)if(!node.group){
            if(node.known&&total>0)node.tooltip+=QStringLiteral("\n%1%").arg(node.weight/total*100,0,'f',2);
        }else node.tooltip=node.name;
        window->setPresentation(processColumnDisplayName(column),QString(),std::move(nodes));
        const QPointer<ProcessDock> guard(this);
        window->processContextRequested=[guard,snapshot,column](const QString& key,QPoint global){
            if(!guard)return;const auto found=std::find_if(snapshot->entries.begin(),snapshot->entries.end(),[&](const auto& e){return !e.group&&e.key==key;});
            if(found==snapshot->entries.end())return;const ProcessTableRow row=found->row;
            guard->clearContextActionBinding();auto target=guard->processActionTargetFromTableRow(row);
            if(target.identityKey.empty())return;guard->m_contextActionRecords.push_back(target);
            guard->m_contextActionIdentityKey=target.identityKey;guard->m_contextActionRecord=target.record;guard->m_hasContextActionRecord=true;
            guard->showBoundProcessContextMenu(global,&row,column);
        };
        window->processActivated=[guard](const QString& key){
            if(!guard)return;const auto index=guard->processTableViewIndexForIdentityKey(key.toStdString(),0);
            if(index.isValid()){auto* selection=guard->m_processTable->selectionModel();if(selection)selection->setCurrentIndex(index,QItemSelectionModel::ClearAndSelect|QItemSelectionModel::Rows);}
        };
    }
    updateMetricAreaState();
}
