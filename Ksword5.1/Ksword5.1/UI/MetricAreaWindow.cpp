#include "MetricAreaWindow.h"
#include "SecondaryPageLayout.h"
#include "PrimaryPageStyle.h"
#include "ToolbarMetrics.h"
#include "TablePresentation.h"
#include "VisibleTableWidget.h"
#include "UI_All.h"
#include "SegmentedControl.h"
#include "../Internationalization/LanguageManager.h"
#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTableView>
#include <QAbstractTableModel>
#include <QHeaderView>
#include <QTimer>
#include <QTabBar>
#include <QSignalBlocker>
#include <QComboBox>
#include <QResizeEvent>

namespace ks::ui {
namespace { QString L(const char* value){return ks::i18n::sourceText(QString::fromUtf8(value));} }
// Plain value rows replace four separately allocated table items per excluded
// node. The model owns its strings/icons, so replacing canvas storage is safe.
class MetricAreaWindow::ExcludedModel final : public QAbstractTableModel {
public:
    explicit ExcludedModel(QObject* parent):QAbstractTableModel(parent){}
    int rowCount(const QModelIndex& parent={})const override{return parent.isValid()?0:static_cast<int>(m_rows.size());}
    int columnCount(const QModelIndex& parent={})const override{return parent.isValid()?0:4;}
    QVariant data(const QModelIndex& index,int role=Qt::DisplayRole)const override{
        if(!index.isValid()||index.row()<0||index.row()>=rowCount()||index.column()<0||index.column()>=4)return {};
        const auto& row=m_rows[static_cast<std::size_t>(index.row())];
        if(role==Qt::UserRole)return row.key;
        if(role==Qt::ToolTipRole)return row.tooltip;
        if(role==Qt::DecorationRole&&index.column()==0)return row.icon;
        if(role!=Qt::DisplayRole)return {};
        switch(index.column()){
        case 0:return row.name;case 1:return row.identity;case 2:return row.value;
        default:return row.known?m_zero:m_unavailable;
        }
    }
    QVariant headerData(int section,Qt::Orientation orientation,int role=Qt::DisplayRole)const override{
        return orientation==Qt::Horizontal&&role==Qt::DisplayRole&&section>=0&&section<m_headers.size()?m_headers[section]:QVariant();
    }
    void setHeaders(QStringList headers){
        m_headers=std::move(headers);m_zero=L("零值");m_unavailable=L("不可用");emit headerDataChanged(Qt::Horizontal,0,3);
        if(rowCount()>0)emit dataChanged(index(0,3),index(rowCount()-1,3),{Qt::DisplayRole});
    }
    void setNodes(const std::vector<MetricAreaNode>& nodes){
        beginResetModel();m_rows.clear();
        for(const auto& node:nodes){
            if(node.group||(node.known&&node.weight>0))continue;
            m_rows.push_back({node.key,node.name,node.identity,node.value,node.tooltip,node.icon,node.known});
        }
        endResetModel();
    }
private:
    struct Row{QString key,name,identity,value,tooltip;QIcon icon;bool known;};
    std::vector<Row> m_rows;
    QStringList m_headers;
    QString m_zero,m_unavailable;
};
MetricAreaWindow::MetricAreaWindow(QWidget* parent):QDialog(parent){
    setAttribute(Qt::WA_DeleteOnClose);setModal(false);setObjectName(QStringLiteral("metric_area_window"));
    setWindowFlag(Qt::WindowContextHelpButtonHint,false);
    setWindowFlag(Qt::WindowMinMaxButtonsHint,true);
    setSizeGripEnabled(true);
    StyleSecondaryWindow(this);
    auto* root=new QVBoxLayout(this);root->setContentsMargins(6,6,6,6);root->setSpacing(6);
    m_modes=new QTabBar(this);m_modes->setObjectName(QStringLiteral("metric_area_modes"));
    m_modes->setExpanding(false);m_modes->setUsesScrollButtons(false);m_modes->setElideMode(Qt::ElideRight);
    m_modes->setSizePolicy(QSizePolicy::Ignored,QSizePolicy::Preferred);m_modes->setMinimumWidth(0);
    InstallSegmentedTabBar(m_modes);m_modes->hide();root->addWidget(m_modes);
    m_modeCombo=new QComboBox(this);m_modeCombo->setObjectName(QStringLiteral("metric_area_mode_combo"));
    m_modeCombo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);m_modeCombo->setMinimumContentsLength(1);
    m_modeCombo->setMinimumWidth(0);m_modeCombo->setSizePolicy(QSizePolicy::Ignored,QSizePolicy::Preferred);
    NormalizeToolbarControl(m_modeCombo);m_modeCombo->hide();root->addWidget(m_modeCombo);
    const auto selectMode=[this](int index){
        if(index<0)return;
        {const QSignalBlocker barBlock(m_modes),comboBlock(m_modeCombo);m_modes->setCurrentIndex(index);m_modeCombo->setCurrentIndex(index);}
        const auto cb=modeChanged;if(cb&&index>=0)cb(index);
    };
    connect(m_modes,&QTabBar::currentChanged,this,selectMode);
    connect(m_modeCombo,&QComboBox::currentIndexChanged,this,selectMode);
    auto* toolbar=new QWidget(this);auto* tools=new QHBoxLayout(toolbar);tools->setContentsMargins(8,6,8,6);
    m_back=new QPushButton(toolbar);m_reset=new QPushButton(toolbar);m_scope=new QLabel(toolbar);
    m_scope->setTextFormat(Qt::PlainText);
    m_scope->setSizePolicy(QSizePolicy::Ignored,QSizePolicy::Preferred);
    tools->addWidget(m_back);tools->addWidget(m_reset);tools->addWidget(m_scope,1);
    StylePrimaryToolbar(toolbar);NormalizeToolbarRow(tools);root->addWidget(toolbar);
    m_canvas=new MetricAreaCanvas(this);StylePrimaryContentPanel(m_canvas,false);root->addWidget(m_canvas,1);
    m_excludedLabel=new QLabel(this);root->addWidget(m_excludedLabel);
    m_excluded=new QTableView(this);m_excluded->setObjectName(QStringLiteral("metric_area_excluded"));
    m_excluded->setProperty("ks_i18n_preserve_model_data",true);
    SetTableActionBarMode(m_excluded,TableActionBarMode::None);ApplyTablePresentation(m_excluded);
    m_excludedModel=new ExcludedModel(m_excluded);m_excluded->setModel(m_excludedModel);
    m_excluded->verticalHeader()->hide();m_excluded->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_excluded->setSelectionMode(QAbstractItemView::SingleSelection);m_excluded->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_excluded->setContextMenuPolicy(Qt::CustomContextMenu);m_excluded->setMaximumHeight(132);
    m_excluded->horizontalHeader()->setSectionResizeMode(0,QHeaderView::Stretch);
    m_excluded->horizontalHeader()->setResizeContentsPrecision(128);
    for(int c=1;c<4;++c)m_excluded->horizontalHeader()->setSectionResizeMode(c,QHeaderView::ResizeToContents);
    root->addWidget(m_excluded);
    m_status=new QLabel(this);m_status->setTextFormat(Qt::PlainText);m_status->setWordWrap(true);StyleSecondaryFooter(m_status);root->addWidget(m_status);
    connect(m_back,&QPushButton::clicked,m_canvas,&MetricAreaCanvas::goBack);
    connect(m_reset,&QPushButton::clicked,m_canvas,&MetricAreaCanvas::resetRoot);
    m_canvas->rootChanged=[this](){
        const int index=m_canvas->rootIndex();m_back->setEnabled(index>=0);m_reset->setEnabled(index>=0);
        m_scope->setText(index>=0?m_canvas->nodes()[index].name:m_allLabel);
        m_scope->setToolTip(m_scope->text());
    };
    m_canvas->contextRequested=[this](int index,QPoint position){const auto key=m_canvas->nodes()[index].key;
        const auto cb=itemContextRequested;if(cb)cb(key,position);};
    m_canvas->activated=[this](int index){const auto key=m_canvas->nodes()[index].key;
        const auto cb=itemActivated;if(cb)cb(key);};
    connect(m_excluded,&QWidget::customContextMenuRequested,this,[this](const QPoint& at){
        const auto index=m_excluded->indexAt(at);if(!index.isValid())return;
        const QString key=index.data(Qt::UserRole).toString();const auto position=m_excluded->viewport()->mapToGlobal(at);
        const auto cb=itemContextRequested;if(cb)cb(key,position);
    });
    connect(m_excluded,&QTableView::clicked,this,[this](const QModelIndex& index){
        const QString key=index.data(Qt::UserRole).toString();
        const auto cb=itemActivated;if(cb)cb(key);
    });
    applyResponsiveWindowGeometry(this,parent,QSize(1100,760),QSize(420,320));retranslate();
}
void MetricAreaWindow::setPresentation(QString metric,QString state,std::vector<MetricAreaNode> nodes){
    m_metric=std::move(metric);m_state=std::move(state);m_canvas->setNodes(std::move(nodes));retranslate();rebuildExcluded();
}
void MetricAreaWindow::updateState(QString state){m_state=std::move(state);m_status->setText(m_state);}
void MetricAreaWindow::setSubject(QString allLabel,QString nameLabel,QString identityLabel,QString interactionHint){
    if(m_customSubject&&m_allLabel==allLabel&&m_nameLabel==nameLabel&&m_identityLabel==identityLabel
        &&m_interactionHint==interactionHint)return;
    m_customSubject=true;m_allLabel=std::move(allLabel);m_nameLabel=std::move(nameLabel);
    m_identityLabel=std::move(identityLabel);m_interactionHint=std::move(interactionHint);retranslate();
}
void MetricAreaWindow::setModes(QStringList labels,int selected){
    const QSignalBlocker blocker(m_modes),comboBlock(m_modeCombo);
    if(m_modeLabels!=labels){
        m_modeLabels=std::move(labels);
        while(m_modes->count()>0)m_modes->removeTab(m_modes->count()-1);
        m_modeCombo->clear();
        for(const auto& label:m_modeLabels){
            const int index=m_modes->addTab(label);m_modes->setTabToolTip(index,label);
            m_modeCombo->addItem(label);m_modeCombo->setItemData(index,label,Qt::ToolTipRole);
        }
    }
    const int index=m_modeLabels.isEmpty()?-1:qBound(0,selected,m_modes->count()-1);
    m_modes->setCurrentIndex(index);m_modeCombo->setCurrentIndex(index);updateModesLayout();
}
int MetricAreaWindow::currentMode()const{return m_modes->currentIndex();}
void MetricAreaWindow::updateModesLayout(){
    if(!m_modes||!m_modeCombo)return;
    const auto margins=layout()->contentsMargins();
    const int available=width()-margins.left()-margins.right();
    const bool any=m_modeLabels.size()>1;
    // A long metric catalog keeps complete option text in a popup rather than
    // compressing segmented labels or forcing the tool window to overflow.
    const bool compact=m_modes->sizeHint().width()>available;
    m_modes->setVisible(any&&!compact);m_modeCombo->setVisible(any&&compact);
}
void MetricAreaWindow::resizeEvent(QResizeEvent* event){QDialog::resizeEvent(event);updateModesLayout();}
void MetricAreaWindow::retranslate(){
    if(!m_customSubject){m_allLabel=L("全部项目");m_nameLabel=L("名称");m_identityLabel=L("标识");
        m_interactionHint=L("双击矩形放大，按退格键返回；单击或右键操作由当前数据页提供。");}
    setWindowTitle(L("矩形面积视图")+QStringLiteral(" · ")+m_metric);
    m_back->setText(L("上一级"));m_reset->setText(L("全部"));
    m_canvas->setToolTip(m_interactionHint);
    m_excludedLabel->setText(L("零值或不可用（不占矩形面积）"));
    m_excludedModel->setHeaders({m_nameLabel,m_identityLabel,m_metric,L("状态")});
    m_excluded->setColumnHidden(1,m_identityLabel.isEmpty());
    m_status->setText(m_state);
    const auto cb=m_canvas->rootChanged;if(cb)cb();
}
void MetricAreaWindow::rebuildExcluded(){
    m_excludedModel->setNodes(m_canvas->nodes());
    const bool any=m_excludedModel->rowCount()>0;m_excludedLabel->setVisible(any);m_excluded->setVisible(any);
}
void MetricAreaWindow::changeEvent(QEvent* e){
    QDialog::changeEvent(e);
    if(!m_canvas || !m_status)return;
    if(e->type()==QEvent::LanguageChange||e->type()==QEvent::ApplicationPaletteChange||e->type()==QEvent::PaletteChange||e->type()==QEvent::FontChange){
        retranslate();updateModesLayout();const auto cb=appearanceChanged;if(cb)QTimer::singleShot(0,this,[cb](){cb();});
    }
}
}
