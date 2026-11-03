#include "../Ksword5.1/Ksword5.1/UI/MetricAreaCanvas.h"
#include "../Ksword5.1/Ksword5.1/UI/MetricAreaWindow.h"
#include <QApplication>
#include <QTest>
#include <QStyle>
#include <QVariant>
#include <QFontDatabase>
#include <QLabel>
#include <QTabBar>
#include <QTableView>
#include <QComboBox>
#include <cassert>
#include <cmath>
#include <iostream>
#include <limits>
using namespace ks::ui;
// Window behavior uses its actual TU. Global application chrome remains a test
// adapter here; full MainWindow/theme acceptance is a separate product check.
namespace ks::ui {
void StyleSecondaryWindow(QWidget*) {}
void StyleSecondaryFooter(QWidget*) {}
void StylePrimaryToolbar(QWidget*) {}
void StylePrimaryContentPanel(QWidget*,bool) {}
void ApplyTablePresentation(QAbstractItemView*,bool) {}
void InstallSegmentedTabBar(QTabBar* bar) { bar->setProperty("test_segmented_installed",true); }
void applyResponsiveWindowGeometry(QWidget* window,QWidget*,const QSize& preferred,const QSize& minimum,double) {
    window->resize(preferred);window->setMinimumSize(minimum);
}
}
__METRIC_PROBE__
static MetricAreaNode node(QString key,double weight,int parent=-1,bool group=false){
    MetricAreaNode n;n.key=key;n.name=key;n.identity=QStringLiteral("1234");n.weight=weight;n.parent=parent;n.group=group;
    n.icon=QApplication::style()->standardIcon(QStyle::SP_ComputerIcon);n.tooltip=key;return n;
}
static double area(QRectF r){return r.width()*r.height();}
static void testGenericWindow(){
    MetricAreaWindow window;window.setAttribute(Qt::WA_DeleteOnClose,false);window.show();QApplication::processEvents();
    auto* modes=window.findChild<QTabBar*>(QStringLiteral("metric_area_modes"));
    assert(modes&&modes->property("test_segmented_installed").toBool());
    assert(window.currentMode()==-1&&modes->isHidden());
    int changes=0,last=-1;
    window.modeChanged=[&](int index){++changes;last=index;};
    const QStringList labels{QStringLiteral("Up"),QStringLiteral("Down"),QStringLiteral("Total")};
    window.setModes(labels,2);assert(window.currentMode()==2&&changes==0&&!modes->isHidden());
    window.setModes(labels,2);assert(modes->count()==3&&changes==0);
    QTest::mouseClick(modes,Qt::LeftButton,Qt::NoModifier,modes->tabRect(0).center());
    assert(changes==1&&last==0&&window.currentMode()==0);
    window.setPresentation(QStringLiteral("Bytes"),QStringLiteral("Snapshot"),{node(QStringLiteral("zero"),0)});
    assert(window.currentMode()==0);auto* excluded=window.findChild<QTableView*>(QStringLiteral("metric_area_excluded"));
    assert(excluded&&excluded->model()->rowCount()==1&&excluded->model()->index(0,1).data().toString()==QStringLiteral("1234"));
    window.setSubject(QStringLiteral("All regions"),QStringLiteral("Region"),QString(),QStringLiteral("Select region"));
    assert(excluded->isColumnHidden(1)&&excluded->model()->headerData(0,Qt::Horizontal).toString()==QStringLiteral("Region"));
    assert(window.canvas()->toolTip()==QStringLiteral("Select region"));
    window.setSubject(QStringLiteral("All owners"),QStringLiteral("Owner"),QStringLiteral("Identity"),QStringLiteral("Details"));
    assert(!excluded->isColumnHidden(1)&&excluded->model()->headerData(1,Qt::Horizontal).toString()==QStringLiteral("Identity"));
    QString activated;window.itemActivated=[&](QString key){activated=std::move(key);};
    QTest::mouseClick(excluded->viewport(),Qt::LeftButton,Qt::NoModifier,excluded->visualRect(excluded->model()->index(0,0)).center());
    assert(activated==QStringLiteral("zero"));
    window.modeChanged=[&](int index){++changes;last=index;window.setModes(labels,0);};
    QTest::mouseClick(modes,Qt::LeftButton,Qt::NoModifier,modes->tabRect(1).center());
    assert(changes==2&&last==1&&window.currentMode()==0);
    window.setModes({},0);assert(window.currentMode()==-1&&modes->isHidden()&&changes==2);
    auto* modeCombo=window.findChild<QComboBox*>(QStringLiteral("metric_area_mode_combo"));assert(modeCombo);
    QStringList longLabels;for(int index=0;index<8;++index)longLabels.append(QStringLiteral("Long memory metric number %1").arg(index));
    window.setModes(longLabels,3);window.resize(460,700);QApplication::processEvents();
    assert(modes->isHidden()&&!modeCombo->isHidden()&&modeCombo->count()==8&&modeCombo->currentIndex()==3);
    assert(modeCombo->itemText(7)==longLabels[7]&&window.currentMode()==3&&changes==2);
    window.modeChanged=[&](int index){++changes;last=index;};
    QTest::keyClick(modeCombo,Qt::Key_Down);assert(changes==3&&last==4&&window.currentMode()==4);
    window.resize(3000,700);QApplication::processEvents();
    assert(!modes->isHidden()&&modeCombo->isHidden()&&modes->currentIndex()==4&&changes==3);
    window.setModes(longLabels,4);assert(changes==3&&window.currentMode()==4);
    std::vector<MetricAreaNode> excludedNodes;excludedNodes.reserve(100000);
    for(int index=0;index<100000;++index)excludedNodes.push_back(node(QString::number(index),0));
    window.setPresentation(QStringLiteral("Bytes"),QStringLiteral("Large snapshot"),std::move(excludedNodes));
    assert(excluded->model()->rowCount()==100000);
    assert(excluded->model()->index(99999,0).data(Qt::UserRole).toString()==QStringLiteral("99999"));
    auto unavailable=node(QStringLiteral("replacement"),1);unavailable.known=false;
    window.setPresentation(QStringLiteral("Bytes"),QStringLiteral("Replacement"),{unavailable});
    assert(excluded->model()->rowCount()==1&&excluded->model()->index(0,0).data(Qt::UserRole).toString()==QStringLiteral("replacement"));
    assert(!excluded->model()->data(excluded->model()->index(99999,0)).isValid());
    auto* deleting=new MetricAreaWindow;auto* deletingModes=deleting->findChild<QTabBar*>(QStringLiteral("metric_area_modes"));
    deleting->setModes(labels,2);deleting->show();QApplication::processEvents();
    deleting->modeChanged=[deleting](int){delete deleting;};
    // Synchronous deletion from a callback must not be followed by window access.
    deletingModes->setCurrentIndex(0);
}
int main(int argc,char** argv){
    QApplication app(argc,argv);QFontDatabase::addApplicationFont(QStringLiteral("C:/Windows/Fonts/msyh.ttc"));
    using Column=MetricProbe::TableColumn;
    for(auto column:{Column::Cpu,Column::CpuCore,Column::Disk,Column::Net,Column::WorkingSet,Column::CommitSize,
        Column::HandleCount,Column::ThreadCount,Column::Gpu,Column::GpuDedicatedMemory,Column::IoReadBytes,
        Column::PageFaultDelta,Column::CycleTime})assert(MetricProbe::isMetricAreaColumn(static_cast<int>(column)));
    for(auto column:{Column::Pid,Column::ParentPid,Column::SessionId,Column::BasePriority,Column::StartTime,
        Column::Protection,Column::R0Status,Column::Path,Column::Status,Column::IsAdmin,Column::HandleTable,
        Column::InjectionSurface,Column::Ram,Column::Count})assert(!MetricProbe::isMetricAreaColumn(static_cast<int>(column)));
    assert(!MetricProbe::isMetricAreaColumn(-1));
    ks::process::ProcessRecord idle;idle.pid=0;idle.processName="Idle";
    assert(!MetricProbe::metricAreaIncludesProcess(static_cast<int>(Column::Cpu),idle));
    assert(!MetricProbe::metricAreaIncludesProcess(static_cast<int>(Column::CpuCore),idle));
    assert(MetricProbe::metricAreaIncludesProcess(static_cast<int>(Column::WorkingSet),idle));
    idle.pid=999;idle.processName="system idle process";
    assert(!MetricProbe::metricAreaIncludesProcess(static_cast<int>(Column::Cpu),idle));
    idle.processName="application.exe";
    assert(MetricProbe::metricAreaIncludesProcess(static_cast<int>(Column::Cpu),idle));
    ks::process::ProcessRecord traffic;traffic.networkUsageKnown=true;traffic.netTxKBps=3;traffic.netRxKBps=11;traffic.netKBps=999;
    assert(MetricProbe::metricAreaNetworkValue(traffic,0)==3);
    assert(MetricProbe::metricAreaNetworkValue(traffic,1)==11);
    assert(MetricProbe::metricAreaNetworkValue(traffic,2)==14);
    assert(MetricProbe::metricAreaNetworkValue(traffic,-1)==-1);
    assert(MetricProbe::metricAreaNetworkValue(traffic,3)==-1);
    traffic.netRxKBps=std::numeric_limits<double>::quiet_NaN();
    assert(MetricProbe::metricAreaNetworkValue(traffic,0)==3);
    assert(MetricProbe::metricAreaNetworkValue(traffic,1)==-1);
    assert(MetricProbe::metricAreaNetworkValue(traffic,2)==-1);
    traffic.netRxKBps=std::numeric_limits<double>::infinity();
    assert(MetricProbe::metricAreaNetworkValue(traffic,1)==-1&&MetricProbe::metricAreaNetworkValue(traffic,2)==-1);
    traffic.netRxKBps=-1;
    assert(MetricProbe::metricAreaNetworkValue(traffic,1)==-1&&MetricProbe::metricAreaNetworkValue(traffic,2)==-1);
    traffic.netTxKBps=traffic.netRxKBps=std::numeric_limits<double>::max();
    assert(MetricProbe::metricAreaNetworkValue(traffic,2)==-1);
    traffic.netTxKBps=traffic.netRxKBps=0;
    assert(MetricProbe::metricAreaNetworkValue(traffic,2)==0);
    app.setFont(QFont(QStringLiteral("Microsoft YaHei"),10));
    testGenericWindow();
    MetricAreaCanvas canvas;canvas.resize(900,600);canvas.show();app.processEvents();
    canvas.setNodes({node(QStringLiteral("group"),0,-1,true),node(QStringLiteral("A"),60,0),node(QStringLiteral("B"),40,0)});
    assert(std::fabs(area(canvas.nodeRect(1))/area(canvas.nodeRect(2))-1.5)<1e-6);
    canvas.setNodes({node(QStringLiteral("huge-a"),std::numeric_limits<double>::max()),node(QStringLiteral("huge-b"),std::numeric_limits<double>::max()/2)});
    assert(std::isfinite(area(canvas.nodeRect(0)))&&std::fabs(area(canvas.nodeRect(0))/area(canvas.nodeRect(1))-2)<1e-6);
    assert(canvas.nodeAt(canvas.nodeRect(1).center())==1);
    canvas.setNodes({node(QStringLiteral("parent"),20),node(QStringLiteral("child"),30,0),node(QStringLiteral("other"),50)});
    assert(std::fabs(area(canvas.nodeRect(0))/area(canvas.nodeRect(1))-2.0/3)<1e-6);
    const auto childRect=canvas.nodeRect(1);
    QTest::mouseDClick(&canvas,Qt::LeftButton,Qt::NoModifier,childRect.center().toPoint());
    assert(canvas.rootIndex()==1&&area(canvas.nodeRect(1))>area(childRect));
    canvas.setNodes({node(QStringLiteral("parent"),25),node(QStringLiteral("child"),35,0),node(QStringLiteral("other"),10)});
    assert(canvas.rootIndex()==1);QTest::keyClick(&canvas,Qt::Key_Backspace);assert(canvas.rootIndex()==0);
    canvas.resetRoot();assert(canvas.rootIndex()==-1);
    QString clicked;
    canvas.contextRequested=[&](int index,QPoint){
        clicked=canvas.nodes()[index].key;
        // Reentrant replacement must never leave old hit indices or an invalid callback on stack.
        canvas.setNodes({node(QStringLiteral("replacement"),1)});
        canvas.contextRequested={};
    };
    QTest::mouseClick(&canvas,Qt::RightButton,Qt::NoModifier,canvas.nodeRect(1).center().toPoint());
    assert(clicked==QStringLiteral("child"));assert(canvas.nodeAt(canvas.rect().center())==0);
    auto unknown=node(QStringLiteral("unknown"),1);unknown.known=false;
    canvas.setNodes({node(QStringLiteral("zero"),0),unknown,node(QStringLiteral("positive"),1)});
    assert(canvas.nodeRect(0).isEmpty()&&canvas.nodeRect(1).isEmpty()&&!canvas.nodeRect(2).isEmpty());
    canvas.setNodes({node(QStringLiteral("negative"),-1),node(QStringLiteral("infinite"),std::numeric_limits<double>::infinity()),node(QStringLiteral("valid"),1)});
    assert(!canvas.nodes()[0].known&&!canvas.nodes()[1].known&&canvas.nodeRect(0).isEmpty()&&canvas.nodeRect(1).isEmpty());
    canvas.resize(150,120);app.processEvents();
    assert(canvas.rect().contains(canvas.nodeRect(2).toAlignedRect()));
    for(bool dark:{false,true}){
        QPalette palette=canvas.palette();palette.setColor(QPalette::Base,dark?QColor(22,24,28):QColor(250,250,250));
        palette.setColor(QPalette::Text,dark?Qt::white:Qt::black);canvas.setPalette(palette);canvas.grab();
    }
    std::vector<MetricAreaNode> deep;
    for(int i=0;i<20000;++i)deep.push_back(node(QString::number(i),1,i-1));
    canvas.resize(900,600);canvas.setNodes(std::move(deep));assert(!canvas.nodeRect(0).isEmpty());
    canvas.setNodes({node(QStringLiteral("cycle-a"),1,1),node(QStringLiteral("cycle-b"),1,0)});
    assert(canvas.nodeAt(canvas.rect().center())>=0);
    canvas.setNodes({node(QStringLiteral("invalid-parent"),1,999)});
    QTest::mouseDClick(&canvas,Qt::LeftButton,Qt::NoModifier,canvas.nodeRect(0).center().toPoint());
    assert(canvas.rootIndex()==0);canvas.goBack();assert(canvas.rootIndex()==-1);canvas.goBack();assert(canvas.rootIndex()==-1);
    std::cout<<"PASS: metric whitelist, network directions, generic modes/subject/activation, 100000 excluded rows, area ratios, nested self weights, zoom/back, stable identity, reentrant context, zero/unavailable, narrow/theme, 20000-node chain and cycle\n";
}
