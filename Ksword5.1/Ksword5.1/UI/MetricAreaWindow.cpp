#include "MetricAreaWindow.h"
#include "SecondaryPageLayout.h"
#include "PrimaryPageStyle.h"
#include "ToolbarMetrics.h"
#include "TablePresentation.h"
#include "VisibleTableWidget.h"
#include "UI_All.h"
#include "../Internationalization/LanguageManager.h"
#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QTimer>

namespace ks::ui {
namespace { QString L(const char* value){return ks::i18n::sourceText(QString::fromUtf8(value));} }
MetricAreaWindow::MetricAreaWindow(QWidget* parent):QDialog(parent){
    setAttribute(Qt::WA_DeleteOnClose);setModal(false);setObjectName(QStringLiteral("metric_area_window"));
    setWindowFlag(Qt::WindowContextHelpButtonHint,false);
    setWindowFlag(Qt::WindowMinMaxButtonsHint,true);
    setSizeGripEnabled(true);
    StyleSecondaryWindow(this);
    auto* root=new QVBoxLayout(this);root->setContentsMargins(6,6,6,6);root->setSpacing(6);
    auto* toolbar=new QWidget(this);auto* tools=new QHBoxLayout(toolbar);tools->setContentsMargins(8,6,8,6);
    m_back=new QPushButton(toolbar);m_reset=new QPushButton(toolbar);m_scope=new QLabel(toolbar);
    m_scope->setSizePolicy(QSizePolicy::Ignored,QSizePolicy::Preferred);
    tools->addWidget(m_back);tools->addWidget(m_reset);tools->addWidget(m_scope,1);
    StylePrimaryToolbar(toolbar);NormalizeToolbarRow(tools);root->addWidget(toolbar);
    m_canvas=new MetricAreaCanvas(this);StylePrimaryContentPanel(m_canvas,false);root->addWidget(m_canvas,1);
    m_excludedLabel=new QLabel(this);root->addWidget(m_excludedLabel);
    m_excluded=new QTableWidget(this);m_excluded->setObjectName(QStringLiteral("metric_area_excluded"));
    m_excluded->setProperty("ks_i18n_preserve_model_data",true);
    SetTableActionBarMode(m_excluded,TableActionBarMode::None);ApplyTablePresentation(m_excluded);
    m_excluded->setColumnCount(4);m_excluded->verticalHeader()->hide();m_excluded->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_excluded->setSelectionMode(QAbstractItemView::SingleSelection);m_excluded->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_excluded->setContextMenuPolicy(Qt::CustomContextMenu);m_excluded->setMaximumHeight(132);
    m_excluded->horizontalHeader()->setSectionResizeMode(0,QHeaderView::Stretch);
    for(int c=1;c<4;++c)m_excluded->horizontalHeader()->setSectionResizeMode(c,QHeaderView::ResizeToContents);
    root->addWidget(m_excluded);
    m_status=new QLabel(this);m_status->setWordWrap(true);StyleSecondaryFooter(m_status);root->addWidget(m_status);
    connect(m_back,&QPushButton::clicked,m_canvas,&MetricAreaCanvas::goBack);
    connect(m_reset,&QPushButton::clicked,m_canvas,&MetricAreaCanvas::resetRoot);
    m_canvas->rootChanged=[this](){
        const int index=m_canvas->rootIndex();m_back->setEnabled(index>=0);m_reset->setEnabled(index>=0);
        m_scope->setText(index>=0?m_canvas->nodes()[index].name:L("全部进程"));
        m_scope->setToolTip(m_scope->text());
    };
    m_canvas->contextRequested=[this](int index,QPoint position){const auto key=m_canvas->nodes()[index].key;
        const auto cb=processContextRequested;if(cb)cb(key,position);};
    m_canvas->activated=[this](int index){const auto key=m_canvas->nodes()[index].key;
        const auto cb=processActivated;if(cb)cb(key);};
    connect(m_excluded,&QWidget::customContextMenuRequested,this,[this](const QPoint& at){
        auto* item=m_excluded->itemAt(at);if(!item)return;auto* name=m_excluded->item(item->row(),0);
        const auto cb=processContextRequested;if(cb)cb(name->data(Qt::UserRole).toString(),m_excluded->viewport()->mapToGlobal(at));
    });
    connect(m_excluded,&QTableWidget::cellClicked,this,[this](int row,int){
        const auto cb=processActivated;if(cb)cb(m_excluded->item(row,0)->data(Qt::UserRole).toString());
    });
    applyResponsiveWindowGeometry(this,parent,QSize(1100,760),QSize(420,320));retranslate();
}
void MetricAreaWindow::setPresentation(QString metric,QString state,std::vector<MetricAreaNode> nodes){
    m_metric=std::move(metric);m_state=std::move(state);m_canvas->setNodes(std::move(nodes));retranslate();rebuildExcluded();
}
void MetricAreaWindow::updateState(QString state){m_state=std::move(state);m_status->setText(m_state);}
void MetricAreaWindow::retranslate(){
    setWindowTitle(L("矩形面积视图")+QStringLiteral(" · ")+m_metric);
    m_back->setText(L("上一级"));m_reset->setText(L("全部"));
    m_canvas->setToolTip(L("双击矩形放大，按退格键返回；右键打开进程菜单。"));
    m_excludedLabel->setText(L("零值或不可用（不占矩形面积）"));
    m_excluded->setHorizontalHeaderLabels({L("进程"),QStringLiteral("PID"),m_metric,L("状态")});
    m_status->setText(m_state);
    const auto cb=m_canvas->rootChanged;if(cb)cb();
}
void MetricAreaWindow::rebuildExcluded(){
    m_excluded->setUpdatesEnabled(false);m_excluded->setRowCount(0);
    for(const auto& n:m_canvas->nodes()){
        if(n.group||(n.known&&n.weight>0))continue;
        const int row=m_excluded->rowCount();m_excluded->insertRow(row);
        auto* name=new QTableWidgetItem(n.icon,n.name);name->setData(Qt::UserRole,n.key);name->setToolTip(n.tooltip);m_excluded->setItem(row,0,name);
        m_excluded->setItem(row,1,new QTableWidgetItem(n.pid));m_excluded->setItem(row,2,new QTableWidgetItem(n.value));
        m_excluded->setItem(row,3,new QTableWidgetItem(n.known?L("零值"):L("不可用")));
    }
    const bool any=m_excluded->rowCount()>0;m_excludedLabel->setVisible(any);m_excluded->setVisible(any);m_excluded->setUpdatesEnabled(true);
}
void MetricAreaWindow::changeEvent(QEvent* e){
    QDialog::changeEvent(e);
    if(!m_canvas || !m_status)return;
    if(e->type()==QEvent::LanguageChange||e->type()==QEvent::ApplicationPaletteChange||e->type()==QEvent::PaletteChange){
        retranslate();const auto cb=appearanceChanged;if(cb)QTimer::singleShot(0,this,[cb](){cb();});
    }
}
}
