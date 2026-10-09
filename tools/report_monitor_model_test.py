from pathlib import Path
from report_property_model_test import function
import argparse, json, os, re, shutil, subprocess

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--qt-root',type=Path,default=Path('.codex-tmp/qt-fixture/ucrt64'))
    parser.add_argument('--compiler',default='g++')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1];app=root/'Ksword5.1/Ksword5.1'
    qt=(root/args.qt_root).resolve();out=root/'work/report-monitor-model-tests';out.mkdir(parents=True,exist_ok=True)
    source=(app/'MonitorDock/MonitorDock.cpp').read_text(encoding='utf-8-sig');header=(app/'MonitorDock/MonitorDock.h').read_text(encoding='utf-8-sig')
    capture=(app/'MonitorDock/ProcessTraceMonitorWidget.Capture.cpp').read_text(encoding='utf-8-sig');capture_header=(app/'MonitorDock/ProcessTraceMonitorWidget.h').read_text(encoding='utf-8-sig')
    model=(app/'UI/StructuredFieldView.cpp').read_text(encoding='utf-8-sig');model=model[:model.index('    StructuredFieldView::StructuredFieldView(')]+'\n}\n'
    model=re.sub(r'#include "([^"\n]+)"',lambda m:'#include "'+(app/'UI'/m[1]).resolve().as_posix()+'"',model)
    (out/'model.cpp').write_text(model,encoding='utf-8')
    structs='\n'.join(function(source,'    struct '+name)+';' for name in ['EtwSchemaPropertyEntry','EtwSchemaEntry','EtwDecodedPropertyEntry','EtwSemanticSummary'])
    producers='\n'.join(function(source,name) for name in ['    QString etwProviderDisplayName(', '    std::uint32_t etwRelatedProcessId(', '    std::uint32_t etwRelatedThreadId(', '    void etwUpdateRelatedIdentity(', '    QByteArray serializeEtwArchiveRow(', '    bool deserializeEtwArchiveRow(', '    QJsonObject buildEtwDetailObject(', '    ks::ui::FieldNode monitorJsonNode('])
    constants='\n'.join(re.findall(r'    constexpr [^;]+kEtwArchive\w+[^;]*;',source[:source.index('    QByteArray serializeEtwArchiveRow(')]))
    event_struct=function(header,'    struct EtwCapturedEventRow')+';'
    property_struct=function(capture_header,'    struct EtwPropertyValue')+';'
    trace_producer=function(capture,'ks::ui::FieldDocument ProcessTraceMonitorWidget::buildEventDetailDocument(').replace('ProcessTraceMonitorWidget::buildEventDetailDocument','buildTraceDocument').replace(') const\n{',')\n{')
    fixture=r'''
#include "Ksword5.1/Ksword5.1/UI/StructuredFieldView.h"
#include "Ksword5.1/Ksword5.1/Internationalization/LanguageManager.h"
#include <winsock2.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <QCoreApplication>
#include <QDataStream>
#include <QBuffer>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QJsonObject>
#include <QJsonArray>
#include <QVariant>
#include <vector>
#include <memory>
#include <limits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
namespace ks::i18n {
 struct LanguageManager::State {};
 LanguageManager::LanguageManager()=default;
 LanguageManager::~LanguageManager()=default;
 LanguageManager& LanguageManager::instance(){static LanguageManager value;return value;}
 QString LanguageManager::sourceText(const QString& source)const{return source;}
 QString LanguageManager::contextText(const QString&,const QString& source)const{return source;}
 bool LanguageManager::eventFilter(QObject* object,QEvent* event){return QObject::eventFilter(object,event);}
}
struct MonitorDock { EVENT_STRUCT };
#define TDH_INTYPE_NULL 0
#define TDH_OUTTYPE_NULL 0
STRUCTS
CONSTANTS
PRODUCERS
PROPERTY_STRUCT
TRACE_PRODUCER
static int checks=0;
static void require(bool value,const char* message){++checks;if(!value){std::fprintf(stderr,"FAIL %s\n",message);std::exit(1);}}
int main(int argc,char**argv){
 QCoreApplication app(argc,argv);
 const QString raw=QStringLiteral("raw_%2:=<>&[x]\n")+QString(8000,QChar(u'A'));
 EVENT_RECORD record{};record.EventHeader.ProcessId=101;record.EventHeader.ThreadId=202;
 record.EventHeader.EventDescriptor.Id=77;record.EventHeader.EventDescriptor.Level=3;record.EventHeader.EventDescriptor.Task=14;
 record.EventHeader.EventDescriptor.Opcode=9;record.EventHeader.EventDescriptor.Keyword=0xF123456789ABCDEFULL;
 record.EventHeader.EventDescriptor.Version=2;record.UserDataLength=64;
 EtwSchemaEntry schema;schema.eventNameText=raw;schema.taskNameText=QStringLiteral("task_%3");schema.opcodeNameText=QStringLiteral("op_%4");
 EtwSemanticSummary semantics{QStringLiteral("resource_%1"),QStringLiteral("action_%2"),raw,QStringLiteral("status_%7")};
 std::vector<EtwDecodedPropertyEntry> properties;
 for(int i=0;i<17;++i){EtwDecodedPropertyEntry property;property.propertyNameText=QStringLiteral("name_%1_%9").arg(i);
 property.normalizedNameText=QStringLiteral("norm_%1").arg(i);property.meaningText=QStringLiteral("meaning_%1").arg(i);
 property.inTypeText=QStringLiteral("type_%1").arg(i);property.valueText=raw+QString::number(i);
 property.hexPreviewText=QStringLiteral("hex_%1").arg(i);property.beginOffset=i;property.endOffset=i+1;property.parseFallback=i%2;
 properties.push_back(property);}
 const QJsonObject payload=buildEtwDetailObject(&record,raw,QStringLiteral("provider_%3"),schema,semantics,properties,63,QStringLiteral("AA BB CC"),false);
 require(payload.value(QStringLiteral("meta")).toObject().value(QStringLiteral("keyword")).toString()==QStringLiteral("0XF123456789ABCDEF"),"keyword retains unsigned 64 bits");
 require(payload.value(QStringLiteral("meta")).toObject().value(QStringLiteral("decode_complete")).toBool()==false,"boolean type retained");
 ks::ui::FieldDocument native;native.nodes.push_back(monitorJsonNode(QStringLiteral("ETW"),payload));
 const auto text=native.toPlainText();
 for(const auto& property:properties){require(text.contains(property.propertyNameText),"provider field name intact");require(text.contains(property.valueText),"full provider value intact");require(text.contains(property.hexPreviewText),"raw byte preview intact");}
 require(text.contains(raw),"complete multiline scalar retained");require(text.contains(QStringLiteral("AA BB CC")),"fallback bytes retained");
 const auto rawNode=monitorJsonNode(QStringLiteral("Security"),raw);require(!rawNode.translateName&&!rawNode.translateValue,"provider keys and values protected from localization");
 MonitorDock::EtwCapturedEventRow original;original.detailObject=payload;original.timestampValue=0xFEDCBA9876543210ULL;
 original.archiveSequence=55;original.decodedReady=true;original.providerName=QStringLiteral("custom_provider");original.headerPid=101;original.headerTid=202;
 original.keywordMaskValue=record.EventHeader.EventDescriptor.Keyword;
 STRING_INITIALIZERS
 const QByteArray archive=serializeEtwArchiveRow(original);MonitorDock::EtwCapturedEventRow restored;
 require(deserializeEtwArchiveRow(archive,&restored),"existing archive binary schema round trips");
 require(restored.detailObject==payload,"archive conserves every JSON key and scalar type");
 require(restored.timestampValue==original.timestampValue&&restored.keywordMaskValue==original.keywordMaskValue,"archive 64 bit values intact");
 STRING_ASSERTIONS
 require(!deserializeEtwArchiveRow(archive.left(archive.size()/2),&restored),"truncated archive rejected");
 std::vector<EtwPropertyValue> traceProperties;for(int i=0;i<9;++i)traceProperties.push_back({QStringLiteral("key_%1_=%2").arg(i),raw+QString::number(i)});
 const auto trace=buildTraceDocument(raw,&record,traceProperties);const auto traceText=trace.toPlainText();
 for(const auto& property:traceProperties){require(traceText.contains(property.nameText),"trace key retained without splitting punctuation");require(traceText.contains(property.valueText),"trace full value retained beyond former summary limits");}
 require(buildTraceDocument(raw,nullptr,traceProperties).isEmpty(),"nullable event produces empty model");
 std::printf("PASS monitor model and archive conservation: %d checks\n",checks);
}
'''
    fields=re.findall(r'^\s*QString (\w+);',event_struct,re.M)
    excluded={'pidTidText','detailVisibleText','detailAllText','providerName'}
    values=[name for name in fields if name not in excluded]
    initializers='\n'.join('original.'+name+'=QStringLiteral("'+name+'_%2\\nraw");' for name in values)
    assertions='\n'.join('require(restored.'+name+'==original.'+name+',"archive '+name+' retained");' for name in values)
    for key,value in {'EVENT_STRUCT':event_struct,'STRUCTS':structs,'CONSTANTS':constants,'PRODUCERS':producers,'PROPERTY_STRUCT':property_struct,'TRACE_PRODUCER':trace_producer,'STRING_INITIALIZERS':initializers,'STRING_ASSERTIONS':assertions}.items():fixture=fixture.replace(key,value)
    (out/'conservation.cpp').write_text(fixture,encoding='utf-8')
    compiler=shutil.which(args.compiler)or args.compiler;flags=['-std=c++20','-O1','-g0','-ffunction-sections','-fdata-sections','-DNOMINMAX','-DUNICODE','-D_UNICODE','-I'+str(root)]
    for module in ['','QtCore','QtGui','QtWidgets']:flags+=['-isystem',str(qt/'include/qt6'/module)]
    objects=[]
    for name in ['model','conservation']:
      obj=out/(name+'.o');subprocess.run([compiler,*flags,'-c',str(out/(name+'.cpp')),'-o',str(obj)],cwd=root,check=True,timeout=180);objects.append(str(obj))
    binary=out/'conservation.exe';subprocess.run([compiler,*objects,'-Wl,--gc-sections','-L'+str(qt/'lib'),'-lQt6Core','-lQt6Gui','-lQt6Widgets','-o',str(binary)],cwd=root,check=True,timeout=120)
    env=dict(os.environ);env['PATH']=str(qt/'bin')+os.pathsep+env.get('PATH','')
    run=subprocess.run([str(binary)],cwd=root,env=env,capture_output=True,text=True,timeout=60)
    log=root/'.codex-build-logs/report-monitor-model-test.json';log.write_text(json.dumps({'exit_code':run.returncode,'stdout':run.stdout,'stderr':run.stderr,'scope':'production pure ETW model/archive and trace producers, no monitor/COM/driver calls'},indent=2),encoding='utf-8')
    print(run.stdout,end='');
    if run.returncode:print(run.stderr);raise SystemExit(run.returncode)
if __name__=='__main__':main()
