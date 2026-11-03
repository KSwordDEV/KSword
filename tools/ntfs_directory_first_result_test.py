"""Exercise exact NTFS directory workers with QtCore; no widgets or filesystem scanning."""
from pathlib import Path
import argparse
import os
import subprocess
from native_msvc_test_support import find_msvc_developer_environment, qt_root
from ntfs_index_projection_test import function

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--source-ref'); args=parser.parse_args()
    path='Ksword5.1/Ksword5.1/FileDock/NtfsSearchPage.cpp'
    page=subprocess.check_output(['git','show',f'{args.source_ref}:{path}'],cwd=ROOT).decode('utf-8-sig') if args.source_ref else (ROOT/path).read_text(encoding='utf-8-sig')
    backend=(ROOT/'Ksword5.1/Ksword5.1/FileDock/NtfsFastIndex.cpp').read_text(encoding='utf-8-sig')
    signature='[](const Request& request, const ks::ui::AsyncOperationToken& token)'
    worker=function(function(page,'void NtfsSearchPage::showDirectory('),signature)
    split='void NtfsSearchPage::loadDirectoryExtensions(' in page
    extension_worker=function(function(page,'void NtfsSearchPage::loadDirectoryExtensions('),signature) if split else ''
    work=ROOT/'.codex-build-logs/ntfs-first-result'; work.mkdir(parents=True,exist_ok=True)
    code=r'''
#include "FileDock/NtfsFastIndex.h"
#include <QDateTime>
#include <QElapsedTimer>
#include <QSet>
#include <QStringList>
#include <algorithm>
#include <limits>
#include <utility>
#include <iostream>
using Index=ks::files::NtfsFastIndex;
using Entry=ks::files::NtfsIndexEntry;
namespace ks::ui { struct AsyncOperationToken { bool canceled=false; bool isCanceled() const {return canceled;} }; }
struct NtfsSpaceMapWidget {
 struct Item { quint64 reference; QString name,path,extension; quint64 bytes; bool directory; };
 struct Data { QVector<Item> items; };
 using DataPtr=std::shared_ptr<const Data>;
 static DataPtr prepare(QVector<Item> items){return std::make_shared<const Data>(Data{std::move(items)});}
};
'''
    code+='namespace ks::files {\n'+function(backend,'QString NtfsFastIndex::fullPath(')+'\n}\n'
    code+=function(page,'quint64 addBytes(')+'\n'
    code+=page[page.index('struct Totals '):page.index('ProjectionPtr project(')]
    code+=page[page.index('struct ExtensionRow '):page.index('class ExtensionModel ')]
    code+=function(page,'QString extension(')+'\n'
    code+='struct Request { ProjectionPtr projection; quint64 reference; bool allocated; };\n'
    code+='int main(){auto run='+worker+';\n'
    if split: code+='auto runExtensions='+extension_worker+';\n'
    code+=r'''
auto snapshot=std::make_shared<ks::files::NtfsIndexSnapshot>();
snapshot->rootReference=1; snapshot->volumeRoot=QStringLiteral("T:\\");
auto projection=std::make_shared<Projection>(); projection->snapshot=snapshot; projection->root=1;
auto add=[&](quint64 id,quint64 parent,bool directory){
 Entry entry; entry.fileReference=id; entry.parentReference=parent;
 entry.name=QString::number(id)+(directory?QString():QStringLiteral(".bin"));
 entry.attributes=directory?0x10U:0; entry.sizeKnown=true; entry.logicalBytes=7; entry.allocatedBytes=16;
 snapshot->entries.insert(id,entry);
 if(id!=parent)projection->children[parent].append(id);
};
add(1,1,true);
projection->directories[1].reference=1; projection->directories[1].path=QStringLiteral("T:\\");
for(quint64 dir=2;dir<102;++dir){
 add(dir,1,true); projection->directories[dir].totals={7000,16000,1000,0};
 for(quint64 file=0;file<1000;++file)add(1000+dir*1000+file,dir,false);
}
Request request{projection,1,true}; ks::ui::AsyncOperationToken token;
QElapsedTimer timer; timer.start(); const auto result=run(request,token);
quint64 descendantFiles=0; for(const auto& row:result.extensions)descendantFiles+=row.files;
std::cout<<"first_result_ms="<<timer.nsecsElapsed()/1e6<<" immediate_items="<<result.map->items.size()
 <<" descendant_files_counted_before_display="<<descendantFiles<<"\n";
if(result.map->items.size()!=100||result.map->items.front().bytes!=16000)return 2;
if(descendantFiles!=0){std::cout<<"FAIL: directory display waits for recursive extension aggregation\n";return 1;}
token.canceled=true; if(run(request,token).map)return 3; token.canceled=false;
'''
    if split:
        code+='const auto extensionResult=runExtensions(request,token); if(extensionResult.extensions.size()!=1||extensionResult.extensions.front().files!=100000||extensionResult.extensions.front().logical!=700000||extensionResult.extensions.front().allocated!=1600000)return 4;\n'
    code+=r'std::cout<<"NTFS_FIRST_RESULT=PASS direct_children_first extension_totals cancellation\n";}'+'\n'
    fixture=work/'fixture.cpp'; fixture.write_text(code,encoding='utf-8')
    qt=qt_root(); command=['cl','/nologo','/std:c++20','/O2','/EHsc','/MD','/W4','/WX','/utf-8','/Zc:__cplusplus','/DNOMINMAX','/external:W0',
      '/external:I'+str(qt/'include'),'/external:I'+str(qt/'include/QtCore'),'/I'+str(ROOT/'Ksword5.1/Ksword5.1'),str(fixture),'/Fe:'+str(work/'test.exe'),'/Fo:'+str(work)+'\\','/link','/LIBPATH:'+str(qt/'lib'),'Qt6Core.lib']
    script=work/'build.cmd'; script.write_text('@echo off\ncall "'+str(find_msvc_developer_environment())+'" -arch=x64 -host_arch=x64 >nul\n'+subprocess.list2cmdline(command)+'\nexit /b %errorlevel%\n',encoding='utf-8')
    subprocess.run(['cmd','/d','/c',str(script)],cwd=work,check=True)
    env=dict(os.environ); env['PATH']=str(qt/'bin')+os.pathsep+env.get('PATH','')
    subprocess.run([str(work/'test.exe')],cwd=work,env=env,check=True)

if __name__=='__main__': main()
