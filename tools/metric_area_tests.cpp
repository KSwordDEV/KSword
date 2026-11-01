#include "../Ksword5.1/Ksword5.1/UI/MetricAreaCanvas.h"
#include <QApplication>
#include <QTest>
#include <QStyle>
#include <QVariant>
#include <QFontDatabase>
#include <cassert>
#include <cmath>
#include <iostream>
using namespace ks::ui;
__METRIC_PROBE__
static MetricAreaNode node(QString key,double weight,int parent=-1,bool group=false){
    MetricAreaNode n;n.key=key;n.name=key;n.pid=QStringLiteral("1234");n.weight=weight;n.parent=parent;n.group=group;
    n.icon=QApplication::style()->standardIcon(QStyle::SP_ComputerIcon);n.tooltip=key;return n;
}
static double area(QRectF r){return r.width()*r.height();}
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
    app.setFont(QFont(QStringLiteral("Microsoft YaHei"),10));
    MetricAreaCanvas canvas;canvas.resize(900,600);canvas.show();app.processEvents();
    canvas.setNodes({node(QStringLiteral("group"),0,-1,true),node(QStringLiteral("A"),60,0),node(QStringLiteral("B"),40,0)});
    assert(std::fabs(area(canvas.nodeRect(1))/area(canvas.nodeRect(2))-1.5)<1e-6);
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
    std::cout<<"PASS: metric whitelist, area ratios, nested self weights, zoom/back, stable identity, reentrant context, zero/unavailable, narrow/theme, 20000-node chain and cycle\n";
}
