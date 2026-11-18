#include <QCoreApplication>
#include <QHash>
#include <QObject>
#include <QPointer>
#include <QStringList>
#include <QVector>
#include <algorithm>
#include <array>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <utility>
#include <vector>

static unsigned checks=0,widgetConstructions=0;
static void check(bool value) { ++checks;if(!value) { std::cerr<<"check failed "<<checks<<'\n';std::abort(); } }
class QWidget : public QObject
{
public:
    QWidget() { ++widgetConstructions; }
    bool isEnabled() const { return enabled; }
    void setEnabled(bool value) { enabled=value; }
private:
    bool enabled=true;
};
class QIcon {};
class QTabWidget final : public QWidget
{
public:
    struct Item { QPointer<QWidget> page;QString text;bool visible=true,enabled=true; };
    QVector<Item> items;QPointer<QWidget> current;unsigned selections=0,iconUpdates=0;
    std::function<void(QWidget*)> onSelect;
    int addTab(QWidget* page,const QIcon&,const QString& title)
    {
        items.append({page,title});if(current.isNull())current=page;return static_cast<int>(items.size())-1;
    }
    int indexOf(const QWidget* page) const
    {
        for(int i=0;i<items.size();++i) if(items[i].page.data()==page) return i;
        return -1;
    }
    void setTabText(int index,const QString& title) { items[index].text=title; }
    void setTabIcon(int,const QIcon&) { ++iconUpdates; }
    QString tabText(int index) const { return items[index].text; }
    bool isTabVisible(int index) const { return items[index].visible; }
    bool isTabEnabled(int index) const { return items[index].enabled; }
    QWidget* currentWidget() const { return current.data(); }
    void setCurrentWidget(QWidget* page)
    {
        if(indexOf(page)<0||current.data()==page)return;
        current=page;++selections;
        const auto callback=onSelect;if(callback)callback(page);
    }
};
namespace ks::i18n
{
    class LanguageManager
    {
        struct Binding {QPointer<QTabWidget> tabs;QPointer<QWidget> page;QString key,fallback;};
        QVector<Binding> bindings;
    public:
        QString language;
        static LanguageManager& instance() {static LanguageManager manager;return manager;}
        QString text(const QString& key,const QString& fallback) const
        {return language.isEmpty()?fallback:language+QStringLiteral(":")+key;}
        void bindTab(QTabWidget* tabs,QWidget* page,const QString& key,const QString& fallback)
        {bindings.append({tabs,page,key,fallback});tabs->setTabText(tabs->indexOf(page),text(key,fallback));}
        void retranslate(const QString& next)
        {
            language=next;
            for(const auto& binding:bindings) if(binding.tabs&&binding.page)
            {
                const int index=binding.tabs->indexOf(binding.page.data());
                if(index>=0)binding.tabs->setTabText(index,text(binding.key,binding.fallback));
            }
        }
    };
}
#include "__CATALOG_HEADER__"
class ProcessDock final : public QWidget
{
public:
    static ks::ui::PageNavigationCatalog navigationCatalog(const ProcessDock* existing=nullptr);
    QWidget* activateNavigationDescriptor(const QString& id);
__NAVIGATION_DECLARATIONS__
};
__ACTUAL_METHODS__
__ACTUAL_REGISTRATION__

struct Fixture
{
    std::unique_ptr<ProcessDock> dock=std::make_unique<ProcessDock>();
    QTabWidget top,inner,list;
    std::array<std::unique_ptr<QWidget>,9> pages;
    Fixture()
    {
        for(auto& page:pages)page=std::make_unique<QWidget>();
        const std::array<int,9> order{7,8,0,1,3,4,2,5,6};
        for(const int row:order) dock->registerNavigationTab(static_cast<ProcessDock::NavigationPage>(row),
            row>=7?&list:row==3||row==4?&inner:&top,pages[static_cast<std::size_t>(row)].get());
    }
    QStringList trace;
    void observe()
    {
        top.onSelect=[this](QWidget* page){trace.append(QStringLiteral("top:")+QString::number(top.indexOf(page)));};
        inner.onSelect=[this](QWidget* page){trace.append(QStringLiteral("inner:")+QString::number(inner.indexOf(page)));};
        list.onSelect=[this](QWidget* page){trace.append(QStringLiteral("list:")+QString::number(list.indexOf(page)));};
    }
};
int main(int argc,char** argv)
{
    QCoreApplication app(argc,argv);
    const unsigned coldBefore=widgetConstructions;
    const auto cold=ProcessDock::navigationCatalog();check(cold.size()==9&&widgetConstructions==coldBefore);
    const QStringList ids{QStringLiteral("list"),QStringLiteral("threads"),QStringLiteral("cross_view"),
        QStringLiteral("cross_view.process"),QStringLiteral("cross_view.thread"),QStringLiteral("create"),QStringLiteral("deep_detection"),
        QStringLiteral("list.processes"),QStringLiteral("list.detection")};
    for(int i=0;i<cold.size();++i)
    {
        check(cold[i].id==ids[i]&&cold[i].visible&&cold[i].enabled&&!cold[i].title.isEmpty());
        check(cold[i].searchTexts.contains(cold[i].title));
        check(cold[i].parentId==(i>=7?QStringLiteral("list"):i==3||i==4?QStringLiteral("cross_view"):QString()));
    }
    const auto resolved=ks::ui::ResolvePageNavigationCatalog(cold,QStringLiteral("Process"));check(resolved&&resolved->size()==9);
    check((*resolved)[7].page.current&&!(*resolved)[8].page.current&&(*resolved)[8].depth==2);
    check((*resolved)[0].page.current&&!(*resolved)[3].page.current&&(*resolved)[3].depth==2);
    const auto registryCold=ks::ui::RegisteredPageNavigationCatalog(QStringLiteral("process"),nullptr);
    check(registryCold&&registryCold->size()==9&&widgetConstructions==coldBefore);
    check(!ks::ui::RegisteredPageNavigationCatalog(QStringLiteral("not-process"),nullptr));
    check(ks::ui::NavigateRegisteredPageNavigationCatalog(QStringLiteral("process"),nullptr,ids[0])==nullptr);
    {
        Fixture fixture;fixture.observe();
        const auto warm=ProcessDock::navigationCatalog(fixture.dock.get());
        for(int i=0;i<warm.size();++i)check(warm[i].id==cold[i].id&&warm[i].title==cold[i].title);
        check(warm[0].current&&warm[3].current&&!warm[2].current);
        // Factory registration is idempotent and keeps icon/title/widget identity.
        fixture.dock->registerNavigationTab(ProcessDock::NavigationPage::List,&fixture.top,fixture.pages[0].get(),QIcon());
        check(fixture.top.items.size()==5&&fixture.top.iconUpdates==1);
        check(fixture.dock->activateNavigationDescriptor(ids[6])==fixture.pages[6].get());
        fixture.trace.clear();
        check(fixture.dock->activateNavigationDescriptor(ids[8])==fixture.pages[8].get());
        check(fixture.trace==QStringList({QStringLiteral("top:0"),QStringLiteral("list:1")}));
        fixture.trace.clear();
        check(fixture.dock->activateNavigationDescriptor(QStringLiteral("unknown"))==nullptr&&fixture.trace.isEmpty());
        check(fixture.dock->activateNavigationDescriptor(ids[4])==fixture.pages[4].get());
        check(fixture.trace==QStringList({QStringLiteral("top:2"),QStringLiteral("inner:1")}));
        const auto current=ks::ui::ResolvePageNavigationCatalog(ProcessDock::navigationCatalog(fixture.dock.get()),QStringLiteral("Process"));
        check(current&&(*current)[2].page.current&&(*current)[4].page.current&&!(*current)[3].page.current);
        fixture.trace.clear();check(fixture.dock->activateNavigationDescriptor(ids[4])==fixture.pages[4].get());check(fixture.trace.isEmpty());
        check(ks::ui::NavigateRegisteredPageNavigationCatalog(QStringLiteral("process"),fixture.dock.get(),ids[1])==fixture.pages[1].get());
        fixture.trace.clear();fixture.inner.items[1].visible=false;
        check(fixture.dock->activateNavigationDescriptor(ids[4])==nullptr&&fixture.trace.isEmpty());
        fixture.inner.items[1].visible=true;fixture.inner.items[1].enabled=false;
        check(fixture.dock->activateNavigationDescriptor(ids[4])==nullptr&&fixture.trace.isEmpty());
        fixture.inner.items[1].enabled=true;fixture.top.items[2].enabled=false;
        const auto unavailable=ks::ui::ResolvePageNavigationCatalog(ProcessDock::navigationCatalog(fixture.dock.get()),QStringLiteral("Process"));
        check(unavailable&&!(*unavailable)[4].page.enabled);
        check(fixture.dock->activateNavigationDescriptor(ids[4])==nullptr&&fixture.trace.isEmpty());
        fixture.top.items[2].enabled=true;fixture.top.setEnabled(false);
        check(fixture.dock->activateNavigationDescriptor(ids[4])==nullptr&&fixture.trace.isEmpty());
        fixture.top.setEnabled(true);
        // A disabled busy content table is still a navigable real Tab.
        fixture.pages[4]->setEnabled(false);
        check(ProcessDock::navigationCatalog(fixture.dock.get())[4].enabled);
        check(fixture.dock->activateNavigationDescriptor(ids[4])==fixture.pages[4].get());
        ks::i18n::LanguageManager::instance().retranslate(QStringLiteral("en-US"));
        const auto translated=ProcessDock::navigationCatalog(fixture.dock.get());
        const auto translatedCold=ProcessDock::navigationCatalog();
        for(int i=0;i<ids.size();++i)check(translated[i].title==translatedCold[i].title&&translated[i].id==ids[i]);
        fixture.top.setTabText(0,QStringLiteral("actual dynamic title"));
        check(ProcessDock::navigationCatalog(fixture.dock.get())[0].title==QStringLiteral("actual dynamic title"));
        fixture.pages[4].reset();check(!ProcessDock::navigationCatalog(fixture.dock.get())[4].visible);
        check(fixture.dock->activateNavigationDescriptor(ids[4])==nullptr);
    }
    {
        Fixture fixture;
        fixture.top.onSelect=[&](QWidget*){fixture.inner.items[1].enabled=false;};
        check(fixture.dock->activateNavigationDescriptor(ids[4])==nullptr&&fixture.inner.selections==0);
    }
    {
        Fixture fixture;
        fixture.top.onSelect=[&](QWidget*){fixture.pages[4].reset();};
        check(fixture.dock->activateNavigationDescriptor(ids[4])==nullptr&&fixture.inner.selections==0);
    }
    {
        Fixture fixture;
        fixture.top.onSelect=[&](QWidget*){fixture.dock.reset();};
        auto* target=fixture.dock.get();check(target->activateNavigationDescriptor(ids[4])==nullptr&&fixture.inner.selections==0);
    }
    {
        Fixture fixture;
        fixture.top.onSelect=[&](QWidget* page){if(page==fixture.pages[2].get())fixture.top.setCurrentWidget(fixture.pages[0].get());};
        check(fixture.dock->activateNavigationDescriptor(ids[4])==nullptr&&fixture.inner.selections==0);
    }
    {
        Fixture fixture;
        fixture.inner.onSelect=[&](QWidget*){fixture.top.setCurrentWidget(fixture.pages[0].get());};
        check(fixture.dock->activateNavigationDescriptor(ids[4])==nullptr);
    }
    ks::i18n::LanguageManager::instance().retranslate(QStringLiteral("zh-CN"));
    const auto chinese=ProcessDock::navigationCatalog();check(chinese.size()==9&&chinese[0].title.startsWith(QStringLiteral("zh-CN:")));
    std::cout<<"{\"result\":\"passed\",\"checks\":"<<checks<<",\"cold_widget_constructions\":0,\"scope\":\"actual catalog/factory/navigation methods + actual central header; QtCore QObject fakes only\"}\n";
}
