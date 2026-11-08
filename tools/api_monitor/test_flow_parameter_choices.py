"""Exercise real parameter-choice wrapping with FlowLayout, including a negative control."""
import argparse
import ast
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / 'Ksword5.1/Ksword5.1'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--flow-source-ref')
    parser.add_argument('--parameter-source-ref')
    parser.add_argument('--expect-collapsed', action='store_true')
    parser.add_argument('--output-directory', type=Path)
    args = parser.parse_args()
    source = (APP/'UI/ParameterWorkspace.cpp').read_text(encoding='utf-8-sig')
    if args.parameter_source_ref:
        source = subprocess.check_output(['git', 'show', args.parameter_source_ref+':Ksword5.1/Ksword5.1/UI/ParameterWorkspace.cpp'], cwd=ROOT).decode('utf-8-sig')
    begin = source.index('    class ParameterChoiceWrap final')
    end = source.index('    // 仅用于参数滚动正文', begin)
    choice = source[begin:end]
    ui = (APP/'MonitorDock/WinAPIDock.Ui.cpp').read_text(encoding='utf-8-sig')
    labels = re.findall(r'm_hook\w+Check = new QCheckBox\(QStringLiteral\("([^"]+)"\)', ui)
    assert len(labels) == 14
    # Use the actual main-window choice rules, including indicator borders and
    # label spacing. A palette alone never exercised the reported split label.
    theme = (APP/'MainWindow.cpp').read_text(encoding='utf-8-sig')
    first = theme.index('"QCheckBox,QRadioButton{spacing:')
    last = theme.index('"QCheckBox::indicator:indeterminate,', first)
    choice_style = ''.join(ast.literal_eval(literal) for literal in re.findall(r'"(?:[^"\\]|\\.)*"', theme[first:last]))
    choice_style = choice_style.replace('__CHECK_ICON__', '"'+(APP/'Resource/Icon/system/ks_control_check_white.svg').as_posix()+'"')
    fixture = r'''
#include <QApplication>
#include <QCheckBox>
#include <QRadioButton>
#include <QFontDatabase>
#include <QLabel>
#include <QMouseEvent>
#include <QPainter>
#include <QPointer>
#include <QStyleOptionButton>
#include <QVBoxLayout>
#include <QSet>
#include <QDir>
#include <cstdio>
#include "UI/FlowLayout.h"
// CHOICE
static int failed=0, cases=0;
static bool collapsed=false;
void Check(bool ok,const char* what) {if(!ok){std::printf("FAIL %s\n",what);++failed;}}
void Settle() {for(int i=0;i<5;++i){QCoreApplication::sendPostedEvents(nullptr,QEvent::LayoutRequest);QCoreApplication::processEvents();}}
int main(int argc,char**argv){
 QApplication app(argc,argv);
 const int fontId=QFontDatabase::addApplicationFont(QStringLiteral("C:/Windows/Fonts/msyh.ttc"));
 const auto families=QFontDatabase::applicationFontFamilies(fontId);
 const QString family=families.isEmpty()?QStringLiteral("Segoe UI"):families.first();
 const QString output=argc>1?QString::fromLocal8Bit(argv[1]):QString();
 const bool negative=argc>2;
 QList<QString> labels={LABELS};
 for(bool themed:{false,true}) for(bool dark:{false,true}) for(int points:{10,14}) for(int width:{200,340,700}) {
  QString style=CHOICE_STYLE;
  style.replace(QStringLiteral("__DISABLED_TEXT__"),QStringLiteral("#808080"));
  style.replace(QStringLiteral("__OUTLINE__"),QStringLiteral("#7590a8"));
  style.replace(QStringLiteral("__SURFACE__"),dark?QStringLiteral("#202328"):QStringLiteral("#f5f6f8"));
  style.replace(QStringLiteral("__SURFACE_ALT__"),dark?QStringLiteral("#303b48"):QStringLiteral("#e8eef6"));
  style.replace(QStringLiteral("__ACCENT__"),QStringLiteral("#409eff"));
  QApplication::setFont(QFont(family,points));
  QWidget host;host.setFixedWidth(width);host.resize(width,1000);
  QPalette palette=app.palette();palette.setColor(QPalette::Window,dark?QColor(32,35,40):QColor(245,246,248));
  palette.setColor(QPalette::WindowText,dark?Qt::white:Qt::black);app.setPalette(palette);app.setStyleSheet(themed?style:QString());
  host.setPalette(palette);host.setAutoFillBackground(true);
  auto* root=new QVBoxLayout(&host);auto* panel=new QWidget(&host);auto* flow=new ks::ui::FlowLayout(panel,0,12,6);
  QList<QCheckBox*> checks;
  for(const QString& text:labels){auto* check=new QCheckBox(text,panel);check->setChecked(true);new ParameterChoiceWrap(check);flow->addWidget(check);checks<<check;}
  root->addWidget(panel);root->addStretch();host.show();Settle();
  int zero=0;QSet<int> rows;
  for(auto* check:checks){if(check->width()<=0)++zero;rows.insert(check->y());Check(check->isChecked(),"selection preserved");}
  if(negative){collapsed=zero==14;std::printf("NEGATIVE_CONTROL zero_width=%d\n",zero);return collapsed?0:2;}
  Check(zero==0,"all 14 choices have nonzero width");
  for(auto* check:checks){
   Check(check->isVisible(),"choice remains visible");Check(check->geometry().right()<panel->width(),"choice stays in available width");
   const int singleLineHeight=qMax(28,check->fontMetrics().height()+6);
   if(check->minimumHeight()>singleLineHeight)
    std::printf("SPLIT themed=%d points=%d width=%d text=%s hint=%d actual=%d height=%d single=%d\n",themed,points,width,qPrintable(check->text()),check->sizeHint().width(),check->width(),check->minimumHeight(),singleLineHeight);
   Check(check->minimumHeight()<=singleLineHeight,"short API label stays on one line");
  }
  if(width==200)Check(rows.size()>1,"narrow choices wrap");
  auto* first=checks.first();const QPointF point(first->rect().center());
  QMouseEvent press(QEvent::MouseButtonPress,point,point,point,Qt::LeftButton,Qt::LeftButton,Qt::NoModifier);
  QMouseEvent release(QEvent::MouseButtonRelease,point,point,point,Qt::LeftButton,Qt::NoButton,Qt::NoModifier);
  QApplication::sendEvent(first,&press);QApplication::sendEvent(first,&release);Check(!first->isChecked(),"label click toggles original checkbox");
  first->setChecked(true);
  if(!output.isEmpty()){QDir().mkpath(output);host.grab().save(output+QStringLiteral("/choices-%1-%2-%3-%4.png").arg(themed?"main-theme":"native").arg(dark?"dark":"light").arg(points).arg(width));}
  ++cases;
 }
 std::printf("FLOW_PARAMETER_CHOICES cases=%d failures=%d\n",cases,failed);return failed?1:0;
}
'''.replace('// CHOICE', choice)
    fixture = fixture.replace('LABELS', ','.join('QString::fromUtf8('+json.dumps(label,ensure_ascii=False)+')' for label in labels))
    fixture = fixture.replace('CHOICE_STYLE', 'QString::fromUtf8('+json.dumps(choice_style,ensure_ascii=False)+')')
    qt = Path(os.environ.get('KSWORD_QT_DIR', r'D:\Software\Qt\6.9.3\msvc2022_64'))
    with tempfile.TemporaryDirectory(prefix='ksword-flow-choices-') as temporary:
        folder=Path(temporary); cpp=folder/'fixture.cpp';cpp.write_text(fixture,encoding='utf-8')
        flow=APP/'UI/FlowLayout.cpp'
        if args.flow_source_ref:
            flow=folder/'FlowLayout.cpp'
            flow.write_bytes(subprocess.check_output(['git','show',args.flow_source_ref+':Ksword5.1/Ksword5.1/UI/FlowLayout.cpp'],cwd=ROOT))
        exe=folder/'fixture.exe'
        command=['cl','/nologo','/std:c++17','/Zc:__cplusplus','/permissive-','/EHsc','/MD','/utf-8',
                 '/I'+str(APP),'/I'+str(APP/'UI'),'/I'+str(qt/'include')]
        command += ['/I'+str(qt/'include'/module) for module in ['QtWidgets','QtGui','QtCore']]
        command += [str(cpp),str(flow),'/Fo:'+str(folder)+'\\','/Fe:'+str(exe),'/link','/LIBPATH:'+str(qt/'lib'),
                    'Qt6Widgets.lib','Qt6Gui.lib','Qt6Core.lib']
        subprocess.run(command,check=True,cwd=ROOT)
        environment=os.environ.copy();environment['PATH']=str(qt/'bin')+os.pathsep+environment['PATH']
        environment['QT_QPA_PLATFORM']='offscreen';environment['QT_PLUGIN_PATH']=str(qt/'plugins')
        run=[str(exe),str(args.output_directory.resolve()) if args.output_directory else '']
        if args.expect_collapsed:run.append('negative')
        subprocess.run(run,check=True,env=environment,timeout=30,cwd=ROOT)

if __name__=='__main__':main()
