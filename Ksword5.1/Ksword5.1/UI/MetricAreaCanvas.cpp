#include "MetricAreaCanvas.h"
#include "../theme.h"
#include "../Internationalization/LanguageManager.h"
#include <QPainter>
#include <QPainterPath>
#include <QtMath>
#include <QMouseEvent>
#include <QHelpEvent>
#include <QKeyEvent>
#include <QToolTip>
#include <algorithm>
#include <cmath>
#include <numeric>

namespace ks::ui {
namespace {
struct Part { int node; bool own; double weight; };
struct Placement { Part part; QRectF rect; };

// Weight-balanced bisection keeps siblings reasonably square and is bounded by O(n log n).
std::vector<Placement> partition(std::vector<Part> parts, QRectF area) {
    std::stable_sort(parts.begin(), parts.end(), [](const Part& a,const Part& b){return a.weight>b.weight;});
    struct Work { std::size_t first,last; QRectF rect; double weight; };
    const double total=std::accumulate(parts.begin(),parts.end(),0.0,[](double n,const Part& p){return n+p.weight;});
    std::vector<Work> pending{{0,parts.size(),area,total}};
    std::vector<Placement> result;
    while(!pending.empty()) {
        const auto work=pending.back();pending.pop_back();
        if(work.first==work.last || work.weight<=0 || work.rect.isEmpty())continue;
        if(work.last-work.first==1){result.push_back({parts[work.first],work.rect});continue;}
        double leftWeight=0;std::size_t split=work.first;
        while(split+1<work.last && leftWeight+parts[split].weight<=work.weight/2){leftWeight+=parts[split++].weight;}
        if(split==work.first){leftWeight=parts[split++].weight;}
        const double ratio=std::clamp(leftWeight/work.weight,0.0,1.0);
        QRectF left=work.rect,right=work.rect;
        if(work.rect.width()>=work.rect.height()){
            left.setWidth(work.rect.width()*ratio);right.setLeft(left.right());
        }else{left.setHeight(work.rect.height()*ratio);right.setTop(left.bottom());}
        pending.push_back({split,work.last,right,work.weight-leftWeight});
        pending.push_back({work.first,split,left,leftWeight});
    }
    return result;
}
}
MetricAreaCanvas::MetricAreaCanvas(QWidget* parent):QWidget(parent){
    setObjectName(QStringLiteral("metric_area_canvas"));
    setMouseTracking(true);setFocusPolicy(Qt::StrongFocus);
    setSizePolicy(QSizePolicy::Expanding,QSizePolicy::Expanding);
    setMinimumSize(80,80);
    m_renderer.attach(this);
}
void MetricAreaCanvas::setNodes(std::vector<MetricAreaNode> nodes){
    for(auto& node:nodes)if(!std::isfinite(node.weight)||node.weight<0)node.known=false;
    bool sameLayout=m_nodes.size()==nodes.size();
    if(sameLayout)for(std::size_t i=0;i<nodes.size();++i){const auto& a=m_nodes[i];const auto& b=nodes[i];
        if(a.key!=b.key||a.parent!=b.parent||a.weight!=b.weight||a.group!=b.group||a.known!=b.known){sameLayout=false;break;}}
    const QString rootKey=m_root>=0 && m_root<static_cast<int>(m_nodes.size())?m_nodes[m_root].key:QString();
    m_nodes=std::move(nodes);m_root=-1;m_hover=-1;m_surfaceDirty=true;QToolTip::hideText();
    for(int i=0;i<static_cast<int>(m_nodes.size());++i)if(!rootKey.isEmpty()&&m_nodes[i].key==rootKey){m_root=i;break;}
    if(!sameLayout)rebuildLayout();update();
    const auto callback=rootChanged;if(callback)callback();
}
void MetricAreaCanvas::rebuildLayout(){
    m_surfaceDirty=true;m_hover=-1;
    m_boxes.clear();m_children.assign(m_nodes.size(),{});m_totals.assign(m_nodes.size(),0);
    const int count=static_cast<int>(m_nodes.size());
    m_parents.assign(count,-1);auto& parents=m_parents;
    std::vector<int> state(count,0),roots;
    for(int i=0;i<count;++i){const int p=m_nodes[i].parent;if(p>=0&&p<count&&p!=i)parents[i]=p;}
    for(int i=0;i<count;++i){
        int at=i;while(at>=0&&state[at]==0){state[at]=1;int p=parents[at];if(p>=0&&state[p]==1){parents[at]=-1;break;}at=p;}
        at=i;while(at>=0&&state[at]==1){state[at]=2;at=parents[at];}
    }
    for(int i=0;i<count;++i){if(parents[i]>=0)m_children[parents[i]].push_back(i);else roots.push_back(i);}
    std::vector<int> order,pending=roots;
    while(!pending.empty()){int i=pending.back();pending.pop_back();order.push_back(i);for(int c:m_children[i])pending.push_back(c);}
    m_colorAnchors.assign(count, -1);
    for (int i : order) m_colorAnchors[i] = parents[i] >= 0 ? m_colorAnchors[parents[i]] : i;
    // Scale only geometry weights. Raw display values remain caller-owned;
    // summing several individually finite DBL_MAX-sized metrics must not turn
    // partition ratios into infinities/NaNs.
    double maxWeight=0;
    for(const auto& node:m_nodes)if(!node.group&&node.known&&std::isfinite(node.weight))maxWeight=std::max(maxWeight,node.weight);
    for(auto it=order.rbegin();it!=order.rend();++it){int i=*it;const auto& n=m_nodes[i];
        m_totals[i]=!n.group&&n.known&&std::isfinite(n.weight)&&maxWeight>0?std::max(0.0,n.weight)/maxWeight:0;
        for(int c:m_children[i])m_totals[i]+=m_totals[c];
    }
    struct Work{int index;QRectF rect;};
    std::vector<Work> work;
    std::vector<Part> top;
    if(m_root>=0&&m_root<count){if(m_totals[m_root]>0)top.push_back({m_root,false,m_totals[m_root]});}
    else for(int i:roots)if(m_totals[i]>0)top.push_back({i,false,m_totals[i]});
    for(const auto& p:partition(std::move(top),QRectF(rect())))work.push_back({p.part.node,p.rect});
    const qreal header=std::max(22,fontMetrics().height()+8);
    while(!work.empty()){
        const auto item=work.back();work.pop_back();const int i=item.index;
        const QRectF box=item.rect;const auto& n=m_nodes[i];
        std::vector<Part> parts;
        for(int c:m_children[i])if(m_totals[c]>0)parts.push_back({c,false,m_totals[c]});
        if(parts.empty()){if(!n.group)m_boxes.push_back({box,i,false});continue;}
        m_boxes.push_back({box,i,true});
        // At extreme nesting/tiny sizes the parent remains a zoomable summary.
        if(box.width()<28||box.height()<header+8)continue;
        const QRectF inner=box.adjusted(2,header,-2,-2);
        if(!n.group&&n.known&&n.weight>0)parts.push_back({i,true,n.weight/maxWeight});
        for(const auto& p:partition(std::move(parts),inner)){
            if(p.part.own)m_boxes.push_back({p.rect,i,false});else work.push_back({p.part.node,p.rect});
        }
    }
}
int MetricAreaCanvas::boxAt(QPointF point)const{
    for(int i=static_cast<int>(m_boxes.size())-1;i>=0;--i)if(m_boxes[i].rect.contains(point))return i;
    return -1;
}
int MetricAreaCanvas::nodeAt(QPointF point)const{
    const int box=boxAt(point);return box>=0?m_boxes[box].node:-1;
}
QRectF MetricAreaCanvas::nodeRect(int index)const{
    for(auto it=m_boxes.rbegin();it!=m_boxes.rend();++it)if(it->node==index)return it->rect;
    return {};
}
QColor MetricAreaCanvas::boxColor(int index) const
{
    const auto& node = m_nodes[index];
    QColor color = node.background;
    if (!color.isValid()) {
        const int anchor = m_colorAnchors[index];
        const auto& owner = m_nodes[anchor >= 0 ? anchor : index];
        // Members share their group's hue; individual identities add a small variation.
        color = MetricAreaRenderer::identityColor(owner.key.isEmpty() ? owner.name : owner.key,
            palette(), anchor == index ? QString() : node.key);
    }
    if (color.alpha() < 255) {
        color = KswordTheme::BlendColors(palette().color(QPalette::Base), color, color.alpha());
        color.setAlpha(255);
    }
    return color;
}

void MetricAreaCanvas::paintBox(QPainter& body, const Box& box, bool hovered, QPainter* labels) const
{
    const QRectF r = box.rect;
    if (r.isEmpty()) return;
    const auto& node = m_nodes[box.node];
    const QColor color = boxColor(box.node);
    QColor background = m_renderer.paintTile(body, r, color,
        {box.container, hovered, false, hovered && box.container});
    if (hovered && box.container) return;
    QPainter& p = labels ? *labels : body;
    p.save();
    p.setClipRect(r);
    if (box.container) {
        // Group headers are opaque flat navigation surfaces, outside the lighting layer.
        p.fillRect(QRectF(r.left(), r.top(), r.width(),
            std::min<qreal>(r.height(), std::max(22, fontMetrics().height() + 8))), background);
    }

    QRectF content = r.adjusted(4, 3, -4, -3);
    if (box.container) content.setHeight(std::min<qreal>(content.height(), fontMetrics().height() + 2));
    const int iconSize = std::min<int>(16, static_cast<int>(std::min(content.width(), content.height())));
    const bool hasIcon = !node.icon.isNull() && iconSize >= 4;
    const QRectF iconRect(content.topLeft(), QSizeF(iconSize, iconSize));
    if (hasIcon) content.setLeft(content.left() + iconSize + 4);
    if (content.width() > fontMetrics().horizontalAdvance(QStringLiteral("…")) && content.height() >= fontMetrics().height()) {
        QString title = node.name;
        const bool inlineIdentity = !node.identity.isEmpty()
            && fontMetrics().horizontalAdvance(title + QLatin1Char(' ') + node.identity) <= content.width();
        if (inlineIdentity) title += QLatin1Char(' ') + node.identity;
        title = fontMetrics().elidedText(title, Qt::ElideRight, static_cast<int>(content.width()));
        const bool secondLine = !inlineIdentity && !box.container && !node.identity.isEmpty()
            && content.height() >= fontMetrics().height() * 2 + 4
            && content.width() >= fontMetrics().horizontalAdvance(node.identity);
        if (!box.container) {
            // Keep labels readable over both the highlight and the shadow, without framing the tile.
            background = MetricAreaRenderer::captionColor(background, palette());
            const int textWidth = std::max(fontMetrics().horizontalAdvance(title),
                secondLine ? fontMetrics().horizontalAdvance(node.identity) : 0);
            const int labelHeight = fontMetrics().height() * (secondLine ? 2 : 1) + (secondLine ? 4 : 0);
            const qreal left = hasIcon ? iconRect.left() : content.left();
            p.fillRect(QRectF(left - 2, content.top() - 1, content.left() - left + textWidth + 4, labelHeight + 2), background);
        }
        p.setPen(KswordTheme::EnsureTextContrast(node.foreground.isValid() ? node.foreground : palette().color(QPalette::Text), background));
        p.drawText(content, Qt::AlignTop | Qt::AlignLeft, title);
        if (secondLine) p.drawText(content.adjusted(0, fontMetrics().height() + 4, 0, 0), Qt::AlignTop | Qt::AlignLeft, node.identity);
    }
    if (hasIcon) node.icon.paint(&p, iconRect.toAlignedRect());
    p.restore();
}

void MetricAreaCanvas::paintEvent(QPaintEvent*)
{
    const qreal dpr = devicePixelRatioF();
    const QSize pixels(qCeil(width() * dpr), qCeil(height() * dpr));
    if (m_surfaceDirty || m_surface.size() != pixels || m_surface.devicePixelRatio() != dpr) {
        if (m_surface.size() != pixels) m_surface = QPixmap(pixels);
        m_surface.setDevicePixelRatio(dpr);
        m_surface.fill(Qt::transparent);
        if (m_labels.size() != pixels) m_labels = QPixmap(pixels);
        m_labels.setDevicePixelRatio(dpr);
        m_labels.fill(Qt::transparent);
        QPainter labels(&m_labels);
        labels.setFont(font());
        QPainter cache(&m_surface);
        cache.setFont(font());
        cache.setRenderHint(QPainter::SmoothPixmapTransform);
        cache.fillRect(rect(), palette().color(QPalette::Base));
        if (m_boxes.empty()) {
            cache.setPen(palette().color(QPalette::Text));
            cache.drawText(rect().adjusted(16, 16, -16, -16), Qt::AlignCenter | Qt::TextWordWrap,
                ks::i18n::sourceText(QStringLiteral("当前范围没有可绘制的正面积数据。")));
        } else {
            for (const auto& box : m_boxes) paintBox(cache, box, false, &labels);
        }
        std::vector<QRectF> lights;
        lights.reserve(m_boxes.size());
        for (const auto& box : m_boxes) if (!box.container) lights.push_back(box.rect);
        m_renderer.setLightGeometry(size(), lights);
        m_surfaceDirty = false;
    }
    QPainter p(this);
    QPainterPath surface;
    surface.addRoundedRect(QRectF(rect()), 8, 8);
    p.setClipPath(surface);
    p.setRenderHint(QPainter::SmoothPixmapTransform);
    p.drawPixmap(0, 0, m_surface);
    if (m_hover >= 0 && m_hover < static_cast<int>(m_boxes.size())) paintBox(p, m_boxes[m_hover], true);
    m_renderer.paintLights(p);
    p.drawPixmap(0, 0, m_labels);
}
void MetricAreaCanvas::resizeEvent(QResizeEvent* e){QWidget::resizeEvent(e);rebuildLayout();}
void MetricAreaCanvas::mouseMoveEvent(QMouseEvent* e){const int hit=boxAt(e->position());if(hit!=m_hover){m_hover=hit;update();}setCursor(hit>=0?Qt::PointingHandCursor:Qt::ArrowCursor);}
void MetricAreaCanvas::leaveEvent(QEvent* e){m_hover=-1;update();QWidget::leaveEvent(e);}
void MetricAreaCanvas::mousePressEvent(QMouseEvent* e){
    const int hit=nodeAt(e->position());if(hit<0)return;
    if(e->button()==Qt::RightButton){const auto cb=contextRequested;if(cb&&!m_nodes[hit].group)cb(hit,e->globalPosition().toPoint());}
    else if(e->button()==Qt::LeftButton){const auto cb=activated;if(cb&&!m_nodes[hit].group)cb(hit);}
}
void MetricAreaCanvas::focusNode(int index){if(index<0||index>=static_cast<int>(m_nodes.size()))return;m_root=index;rebuildLayout();update();const auto cb=rootChanged;if(cb)cb();}
void MetricAreaCanvas::mouseDoubleClickEvent(QMouseEvent* e){if(e->button()==Qt::LeftButton)focusNode(nodeAt(e->position()));}
void MetricAreaCanvas::resetRoot(){m_root=-1;rebuildLayout();update();const auto cb=rootChanged;if(cb)cb();}
void MetricAreaCanvas::goBack(){if(m_root>=0&&m_root<static_cast<int>(m_parents.size())){m_root=m_parents[m_root];rebuildLayout();update();const auto cb=rootChanged;if(cb)cb();}}
void MetricAreaCanvas::keyPressEvent(QKeyEvent* e){if(e->key()==Qt::Key_Escape||e->key()==Qt::Key_Backspace){goBack();e->accept();}else QWidget::keyPressEvent(e);}
bool MetricAreaCanvas::event(QEvent* e){
    if(e->type()==QEvent::ToolTip){auto* help=static_cast<QHelpEvent*>(e);const int hit=nodeAt(help->pos());
        if(hit>=0)QToolTip::showText(help->globalPos(),m_nodes[hit].tooltip,this);else QToolTip::hideText();return true;}
    if(e->type()==QEvent::FontChange){rebuildLayout();update();}
    if(e->type()==QEvent::PaletteChange||e->type()==QEvent::ApplicationPaletteChange
        ||e->type()==QEvent::LanguageChange||e->type()==QEvent::StyleChange){m_surfaceDirty=true;update();}
    return QWidget::event(e);
}
}
