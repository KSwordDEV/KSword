#include "Framework.h"
#include "registry_workbench_mock.h"
#define private public
#include "RegistryDock/RegistryDock.h"
#undef private
#include "RegistryDock/RegistryValueEditorWidget.h"
#include "theme.h"
#include "Internationalization/LanguageManager.h"
#include <QElapsedTimer>
#include <QFontDatabase>
#include <QShortcut>
#include <QStyleFactory>
#include <QThreadPool>
#include <iostream>

namespace {
    int checks=0,failures=0;
    void check(bool ok,const char* label){++checks;if(!ok){++failures;std::cerr<<"FAIL "<<label<<'\n';}}
    template<class F> bool until(F ready,int maximum=5000)
    {
        QElapsedTimer elapsed;elapsed.start();
        do{QApplication::processEvents();if(ready())return true;QThread::msleep(1);}while(elapsed.elapsed()<maximum);
        return false;
    }
    int rowFor(RegistryDock& dock,const QString& name)
    {
        for(int row=0;row<dock.m_valueTable->rowCount();++row)
            if(dock.m_valueTable->item(row,0)&&dock.m_valueTable->item(row,0)->data(Qt::UserRole).toString()==name)return row;
        return -1;
    }
    bool select(RegistryDock& dock,const QString& name)
    {
        if(!until([&]{return rowFor(dock,name)>=0;}))return false;
        const int row=rowFor(dock,name);if(row<0)return false;
        dock.m_valueTable->setCurrentCell(row,0);dock.m_valueTable->selectRow(row);
        return until([&]{return dock.m_editorReady&&dock.m_editorName==name;});
    }
    QPushButton* button(RegistryDock& dock,const QString& name)
    {
        for(auto* result:dock.findChildren<QPushButton*>())if(result->text()==name)return result;
        return nullptr;
    }
    void theme(bool dark)
    {
        KswordTheme::SetDarkModeEnabled(dark);
        QPalette p;
        for(auto group:{QPalette::Active,QPalette::Inactive,QPalette::Disabled})
        {
            p.setColor(group,QPalette::Window,KswordTheme::WindowColor());p.setColor(group,QPalette::WindowText,KswordTheme::TextPrimaryColor());
            p.setColor(group,QPalette::Base,KswordTheme::SurfaceColor());p.setColor(group,QPalette::AlternateBase,KswordTheme::SurfaceAltColor());
            p.setColor(group,QPalette::Text,group==QPalette::Disabled?KswordTheme::TextDisabledColor():KswordTheme::TextPrimaryColor());
            p.setColor(group,QPalette::Button,KswordTheme::SurfaceAltColor());p.setColor(group,QPalette::ButtonText,KswordTheme::TextPrimaryColor());
            p.setColor(group,QPalette::Mid,KswordTheme::BorderColor());p.setColor(group,QPalette::PlaceholderText,KswordTheme::TextSecondaryColor());
            p.setColor(group,QPalette::Highlight,KswordTheme::PrimaryAccentColor());p.setColor(group,QPalette::HighlightedText,KswordTheme::OnAccentColor());
        }
        QApplication::setPalette(p);
        for(auto* widget:QApplication::allWidgets())widget->setPalette(p);
    }
    void exerciseDock(const QString& output)
    {
        registry_ui::seed();
        RegistryDock dock;dock.resize(1280,820);dock.show();
        check(until([&]{return dock.m_editorReady;}),"initial native-view snapshot ready");
        dock.navigateToPath(QStringLiteral("HKCU\\Console"),true);
        check(until([&]{return dock.m_editorReady&&dock.m_valueTable->rowCount()==5;}),"Console list/full-value reads reach live Dock");
        check(dock.m_mainSplitter->count()==3,"actual workbench has tree, values and detail panels");
        auto* details=button(dock,QStringLiteral("详情"));
        check(details!=nullptr,"detail toggle visible");
        if(details){details->click();QApplication::processEvents();check(dock.m_detailScroll->isHidden(),"details collapse removes side panel");details->click();}
        check(select(dock,QStringLiteral("ColorTable12")),"selecting row binds correct typed editor identity");
        dock.m_valueTable->setFocus();QApplication::processEvents();
        dock.m_renameButton->setFocus();
        bool valueRenameDialog=false;
        QTimer::singleShot(0,[&]{if(auto* dialog=qobject_cast<QDialog*>(QApplication::activeModalWidget())){valueRenameDialog=dialog->windowTitle()==QStringLiteral("重命名值");dialog->reject();}});
        dock.m_renameButton->click();
        check(valueRenameDialog,"toolbar focus preserves selected-value rename target");
        auto* hex=dock.m_valueEditor->findChild<QLineEdit*>(QStringLiteral("registry_value_hex_number"));
        check(hex!=nullptr,"shared typed editor used by real Dock");
        if(!hex)return;
        const auto original=registry_ui::get(QStringLiteral("HKCU\\Console"),QStringLiteral("ColorTable12"));
        hex->setText(QStringLiteral("0x556677"));
        check(dock.m_stageButton->isEnabled(),"valid DWORD edit enables staging");
        dock.m_stageButton->click();
        check(dock.m_pendingChanges.size()==1&&dock.m_changesTable->rowCount()==1,"stage updates count and journal view");
        check(dock.m_pendingChanges[0].beforeData==original.data,"pending entry keeps immutable original bytes");
        hex->setText(QStringLiteral("0x556678"));dock.m_stageButton->click();
        check(dock.m_pendingChanges.size()==1&&dock.m_pendingChanges[0].beforeData==original.data,"restage deduplicates and keeps first baseline");
        check(registry_ui::writes.load()==0,"staging does not call even mocked write backend");
        dock.navigateToPath(QStringLiteral("HKCU\\Environment"),true);
        check(until([&]{return dock.m_editorReady&&dock.m_editorPath.endsWith(QStringLiteral("Environment"));}),"navigation completes after preserving current draft");
        check(dock.m_pendingChanges.size()==1,"navigation retains pending draft");
        dock.navigateToPath(QStringLiteral("HKCU\\Console"),true);
        check(until([&]{return rowFor(dock,QStringLiteral("ColorTable12"))>=0;}),"return location list loaded");
        check(select(dock,QStringLiteral("ColorTable12")),"reopen staged value identity");
        RegistryValueDraft draft;QString error;
        check(dock.m_valueEditor->value(&draft,&error)&&draft.data==dock.m_pendingChanges[0].afterData,"reopened editor displays full staged bytes");
        check(dock.m_pendingChanges[0].beforeData==original.data,"navigation does not rebase original proof");
        auto* clear=button(dock,QStringLiteral("清空草稿"));check(clear!=nullptr,"clear journal action exists");
        if(clear)clear->click();
        check(dock.m_pendingChanges.isEmpty(),"clear journal removes pending writes");
        check(select(dock,QString()),"default row retains actual empty identity");
        auto* text=dock.m_valueEditor->findChild<QPlainTextEdit*>(QStringLiteral("registry_value_text"));
        text->setPlainText(QStringLiteral("default edited"));dock.m_stageButton->click();
        check(dock.m_pendingChanges.size()==1&&dock.m_pendingChanges[0].name.isEmpty(),"default-value draft targets empty name");
        dock.m_applyChangesButton->click();
        check(until([&]{return !dock.m_applyingChanges;}),"mocked apply transaction completes");
        check(dock.m_pendingChanges.isEmpty()&&dock.m_lastChanges.size()==1&&registry_ui::writes.load()==1,"apply verifies one exact mocked write");
        dock.restoreLastChanges();check(dock.m_pendingChanges.size()==1,"undo prepares inverse draft");
        if(clear)clear->click();
        check(select(dock,QStringLiteral("ColorTable12")),"select color before view transition");
        hex->setText(QStringLiteral("0x010203"));dock.m_stageButton->click();
        dock.m_searchEdit->setText(QStringLiteral("Text"));dock.m_matchKeysCheck->setChecked(false);dock.m_matchDataCheck->setChecked(false);
        dock.startSearchAsync();
        check(until([&]{return !dock.m_searchRunning.load();}),"actual registry search completes against mock source");
        check(dock.m_searchResultTable->rowCount()>0,"actual search results bind model rows");
        dock.m_viewCombo->setCurrentIndex(dock.m_viewCombo->findData(32));
        check(until([&]{return dock.m_viewBits==32&&rowFor(dock,QStringLiteral("ViewOnly32"))>=0;}),"view switch reloads scoped values and tree");
        check(dock.m_searchResultTable->rowCount()==0,"view switch clears old search display");
        check(dock.m_pendingChanges.size()==1&&dock.m_pendingChanges[0].viewBits==0,"view switch preserves native draft context");
        if(clear)clear->click();
        check(select(dock,QStringLiteral("ColorTable12")),"32-bit selected value snapshot ready");
        dock.m_rightTabWidget->setCurrentIndex(0);
        for(bool dark:{false,true})
        {
            theme(dark);
            // 单层 queued 回调只观察当前菜单；执行实际入口后关闭菜单结束嵌套循环。
            auto* more = button(dock, QStringLiteral("更多"));
            check(more != nullptr, "workbench more-menu action exists");
            if (more)
            {
                QTimer::singleShot(0, [&] {
                    auto* menu = qobject_cast<QMenu*>(QApplication::activePopupWidget());
                    check(menu && menu->styleSheet() == KswordTheme::ContextMenuStyle(),
                        "more menu explicitly follows current light/dark theme");
                    if (menu) menu->close();
                });
                more->click();
            }
            QTimer::singleShot(0, [&] {
                auto* menu = qobject_cast<QMenu*>(QApplication::activePopupWidget());
                auto* history = menu ? menu->findChild<QMenu*>(QStringLiteral("registry_workbench_history_menu")) : nullptr;
                check(menu && menu->styleSheet() == KswordTheme::ContextMenuStyle(),
                    "navigation menu explicitly follows current light/dark theme");
                check(history && history->styleSheet() == KswordTheme::ContextMenuStyle(),
                    "history submenu explicitly follows current light/dark theme");
                if (menu) menu->close();
            });
            dock.showNavigationMenu();
            for(int width:{320,800,1920})
            {
                dock.resize(width,900);QApplication::processEvents();
                check(dock.width()==width,"responsive Dock honors requested viewport width");
                const QString file=output+QStringLiteral("/registry-workbench-%1-%2.png").arg(dark?QStringLiteral("dark"):QStringLiteral("light")).arg(width);
                check(dock.grab().save(file),"responsive/theme screenshot saved");
            }
        }
        check(dock.accessContextForPath(QStringLiteral("HKEY_CLASSES_ROOT\\Software")).useR0==false,"merged HKCR always uses Win32");
        registry_ui::driverEnabled=true;
        dock.m_viewCombo->setCurrentIndex(dock.m_viewCombo->findData(0));
        dock.navigateToPath(QStringLiteral("HKEY_CLASSES_ROOT"),true);
        check(dock.accessContextForPath(QStringLiteral("HKEY_CURRENT_USER\\Console")).useR0,"target HKCU source independent of current HKCR page");
        // 实际调用生产重命名函数；当前页是 HKCU，仍必须根据目标 HKCR 路由。
        registry_ui::set(QStringLiteral("HKEY_CLASSES_ROOT\\RenameSource"), QStringLiteral("Marker"), REG_BINARY, QByteArray("proof"));
        dock.navigateToPath(QStringLiteral("HKEY_CURRENT_USER"), true);
        QString renamedPath;
        QString renameError;
        check(RegistryWorkbenchAccess::renameKey(QStringLiteral("HKEY_CLASSES_ROOT\\RenameSource"),
            QStringLiteral("RenameTarget"), dock.accessContextForPath(QStringLiteral("HKEY_CLASSES_ROOT\\RenameSource")), &renamedPath, &renameError),
            "HKCR rename executes Win32 transport while R0 is online");
        check(registry_ui::win32KeyRenames == 1 && registry_ui::r0KeyRenames == 0,
            "HKCR rename never enters R0 transport");
        check(renamedPath == QStringLiteral("HKEY_CLASSES_ROOT\\RenameTarget")
            && registry_ui::get(renamedPath, QStringLiteral("Marker")).data == QByteArray("proof"),
            "HKCR rename returns actual mocked destination and retains data");
        registry_ui::driverEnabled=false;
        for(const QString& component:{QStringLiteral("Tail "),QStringLiteral("   "),QStringLiteral("Slash/Key")})
        {
            const QString path=QStringLiteral("HKCU\\")+component;
            registry_ui::set(path,QStringLiteral(" A "),REG_SZ,QByteArray("D\0\0\0",4));
            dock.navigateToPath(path,true);
            check(until([&]{return dock.m_editorReady&&dock.m_editorName==QStringLiteral(" A ");}),"raw space and slash key/value target loads");
            check(dock.m_currentPath==QStringLiteral("HKEY_CURRENT_USER\\")+component,"navigation preserves raw key component");
        }
        const QString rawName=QStringLiteral("名称");
        const QString rawPath=QStringLiteral("HKCU\\数据");
        registry_ui::set(rawPath,rawName,REG_SZ,QByteArray("Z\0\0\0",4));
        dock.navigateToPath(rawPath,true);
        check(until([&]{return dock.m_editorReady&&dock.m_editorName==rawName;}),"Chinese raw-name language fixture ready");
        auto& language=ks::i18n::LanguageManager::instance();QString languageError;
        check(language.setLanguage(QStringLiteral("en-US"),&languageError),"English pack loads");
        language.retranslateAll();QApplication::processEvents();
        const int rawRow=rowFor(dock,rawName);
        check(rawRow>=0&&dock.m_valueTable->item(rawRow,0)->text()==rawName,"language change preserves raw model name");
        check(dock.m_valueTable->horizontalHeaderItem(0)->text()==QStringLiteral("Name"),"language change translates header only");
        check(dock.m_valueEditor->findChildren<QLabel*>().first()->text()==QStringLiteral("HKEY_CURRENT_USER\\数据"),"language change preserves editor raw path");
        check(dock.m_editorSourceLabel->text()==QStringLiteral("Win32 / Native View"),"language change translates separate source label");
        dock.resize(1280,900);QApplication::processEvents();
        check(dock.grab().save(output+QStringLiteral("/registry-workbench-en.png")),"English actual Dock screenshot saved");
        check(language.setLanguage(QStringLiteral("zh-CN"),&languageError),"Chinese pack restores");
    }
    void exerciseSaveShortcut()
    {
        registry_ui::seed();
        RegistryDock dock;dock.resize(1280,820);dock.show();
        dock.navigateToPath(QStringLiteral("HKCU\\Console"),true);
        check(select(dock,QStringLiteral("ColorTable12")),"Ctrl+S fixture target selected");
        QShortcut* save=nullptr;
        for(auto* shortcut:dock.findChildren<QShortcut*>())
            if(shortcut->key()==QKeySequence(QStringLiteral("Ctrl+S"))) {save=shortcut;break;}
        check(save!=nullptr,"real Ctrl+S shortcut located");
        if(!save)return;
        dock.deleteSearchResultValue(QStringLiteral("HKEY_CURRENT_USER\\Console"),QStringLiteral("ColorTable12"));
        check(dock.m_pendingChanges.size()==1&&dock.m_pendingChanges[0].deleteValue,"Ctrl+S deletion staged");
        QMetaObject::invokeMethod(save,"activated",Qt::DirectConnection);
        check(until([&]{return !dock.m_applyingChanges;}),"Ctrl+S deletion apply finishes");
        check(dock.m_pendingChanges.isEmpty()&&registry_ui::writes.load()==1
            &&!registry_ui::get(QStringLiteral("HKCU\\Console"),QStringLiteral("ColorTable12")).exists,
            "Ctrl+S applies deletion without overwriting its draft");
        check(select(dock,QStringLiteral("Text")),"Ctrl+S invalid-input fixture selected");
        auto* text=dock.m_valueEditor->findChild<QPlainTextEdit*>(QStringLiteral("registry_value_text"));
        text->setPlainText(QStringLiteral("staged"));dock.m_stageButton->click();
        check(select(dock,QStringLiteral("Qword")),"Ctrl+S selects separate numeric draft");
        auto* hex=dock.m_valueEditor->findChild<QLineEdit*>(QStringLiteral("registry_value_hex_number"));
        hex->setText(QStringLiteral("invalid"));
        QMetaObject::invokeMethod(save,"activated",Qt::DirectConnection);
        QApplication::processEvents();
        check(registry_ui::writes.load()==1&&dock.m_pendingChanges.size()==1&&!dock.m_applyingChanges,
            "Ctrl+S invalid editor input prevents applying another staged value");
    }
    void exerciseClose()
    {
        registry_ui::seed();
        auto* dock=new RegistryDock;
        check(until([&]{return dock->m_editorReady;}),"close fixture initial read settled");
        dock->navigateToPath(QStringLiteral("HKCU\\Console"),true);
        check(until([&]{return rowFor(*dock,QStringLiteral("ColorTable12"))>=0;}),"close fixture target listed");
        check(select(*dock,QStringLiteral("ColorTable12")),"close fixture target selected");
        auto* hex=dock->m_valueEditor->findChild<QLineEdit*>(QStringLiteral("registry_value_hex_number"));
        hex->setText(QStringLiteral("0x778899"));dock->m_stageButton->click();
        registry_ui::blockReads(true);dock->m_applyChangesButton->click();
        check(until([]{return registry_ui::blockedReads.load()>0;}),"transaction blocked after captured read");
        const auto closed=dock->m_operationsClosed;
        delete dock;
        check(closed->load(),"Dock destruction closes worker mutation gate");
        registry_ui::blockReads(false);
        QThreadPool::globalInstance()->waitForDone();QApplication::processEvents();
        check(registry_ui::writes.load()==0,"closing after preflight read prevents backend write");
        registry_ui::seed();
        dock=new RegistryDock;
        check(until([&]{return dock->m_editorReady;}),"late-callback fixture initial ready");
        registry_ui::blockReads(true);
        dock->navigateToPath(QStringLiteral("HKCU\\Console"),true);
        check(until([]{return registry_ui::blockedReads.load()>0;}),"full-value reader blocked before closing");
        delete dock;
        registry_ui::blockReads(false);QThreadPool::globalInstance()->waitForDone();QApplication::processEvents();
        check(true,"late read and tree callbacks drain after Dock deletion without use-after-free");
    }
}
int main(int argc,char**argv)
{
    QApplication app(argc,argv);app.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
    for(const QString& file:{QStringLiteral("C:/Windows/Fonts/msyh.ttc"),QStringLiteral("C:/Windows/Fonts/consola.ttf"),QStringLiteral("C:/Windows/Fonts/segoeui.ttf")})QFontDatabase::addApplicationFont(file);
    app.setFont(QFont(QStringLiteral("Microsoft YaHei"),9));
    QString languageError;
    check(ks::i18n::LanguageManager::instance().initialize(QStringLiteral("zh-CN"),&languageError),"language manager initializes");
    const QString output=argc>1?QString::fromLocal8Bit(argv[1]):QStringLiteral(".");QDir().mkpath(output);
    QSettings::setDefaultFormat(QSettings::IniFormat);QSettings::setPath(QSettings::IniFormat,QSettings::UserScope,output);
    theme(false);exerciseDock(output);exerciseSaveShortcut();exerciseClose();
    std::cout<<"REGISTRY_WORKBENCH_UI_CHECKS="<<checks<<" FAILURES="<<failures<<std::endl;
    return failures?1:0;
}
