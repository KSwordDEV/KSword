"""Benchmark production lighting into memory images; no widgets, windows or GUI actions."""
from pathlib import Path
import argparse
import os
import subprocess
from native_msvc_test_support import find_msvc_developer_environment, qt_root
from ntfs_index_projection_test import function

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-ref')
    args = parser.parse_args()
    path = 'Ksword5.1/Ksword5.1/UI/MetricAreaRenderer.cpp'
    source = subprocess.check_output(['git', 'show', f'{args.source_ref}:{path}'], cwd=ROOT).decode('utf-8-sig') if args.source_ref else (ROOT/path).read_text(encoding='utf-8-sig')
    batched = 'void MetricAreaRenderer::paintLights(' in source
    work = ROOT/'.codex-build-logs/lighting-benchmark'
    work.mkdir(parents=True, exist_ok=True)
    qt = qt_root()
    declarations = r'''
#include <QGuiApplication>
#include <QImage>
#include <QPixmap>
#include <QPainter>
#include <QPointF>
#include <QSize>
#include <QElapsedTimer>
#include <array>
#include <vector>
#include <algorithm>
#include <cmath>
#include <iostream>
struct Host { int width() const { return 2560; } int height() const { return 1440; } };
class MetricAreaRenderer {
public:
 Host host; Host* m_host=&host;
 QPixmap m_cushion;
 mutable std::array<QPixmap,289> m_directions;
 QPointF m_position; double m_tracking=1;
 QSize m_lightViewport, m_lightPixels;
 std::vector<QRectF> m_lightRects;
 mutable QPixmap m_lightLayer;
 mutable QPointF m_lastLightPosition;
 mutable double m_lastTracking=-1;
 mutable bool m_lightDirty=true;
 const QPixmap& directionalMap(int,int) const;
 void paintLight(QPainter&,const QRectF&) const;
 void setLightGeometry(QSize,const std::vector<QRectF>&);
 void paintLights(QPainter&) const;
};
'''
    code = declarations + function(source, 'QPixmap cushionLightMap(') + '\n'
    for signature in ['const QPixmap& MetricAreaRenderer::directionalMap(', 'void MetricAreaRenderer::paintLight(']:
        code += function(source, signature) + '\n'
    if batched:
        for signature in ['void MetricAreaRenderer::setLightGeometry(', 'void MetricAreaRenderer::paintLights(']:
            code += function(source, signature) + '\n'
    code += r'''
int main(int argc,char** argv) {
 QGuiApplication app(argc,argv);
 for(int count: {100,10000}) {
  MetricAreaRenderer renderer; renderer.m_cushion=cushionLightMap();
  std::vector<QRectF> rectangles;
  const int columns=static_cast<int>(std::sqrt(count)), rows=count/columns;
  for(int y=0;y<rows;++y) for(int x=0;x<columns;++x)
   rectangles.emplace_back(x*2560.0/columns,y*1440.0/rows,2560.0/columns,1440.0/rows);
  SET_GEOMETRY
  QImage image(2560,1440,QImage::Format_ARGB32_Premultiplied);
  QElapsedTimer timer; timer.start();
  double cold=0;
  for(int frame=0;frame<13;++frame) {
   image.fill(Qt::black);
   renderer.m_position=QPointF(900+frame*17,500+frame*9);
   { QPainter painter(&image); DRAW_FRAME }
   if(frame==0){cold=timer.nsecsElapsed()/1e6; timer.restart();}
  }
  std::cout<<"tiles="<<count<<" cold_ms="<<cold<<" steady_ms="<<timer.nsecsElapsed()/1e6/12<<"\n";
 }
}
'''.replace('SET_GEOMETRY', 'renderer.setLightGeometry(QSize(2560,1440),rectangles);' if batched else '').replace('DRAW_FRAME', 'renderer.paintLights(painter);' if batched else 'for(const auto& rectangle:rectangles) renderer.paintLight(painter,rectangle);')
    fixture = work/'benchmark.cpp'
    fixture.write_text(code, encoding='utf-8')
    command = ['cl','/nologo','/std:c++20','/O2','/EHsc','/MD','/W4','/WX','/utf-8','/Zc:__cplusplus','/DNOMINMAX','/external:W0']
    command += ['/external:I'+str(qt/'include'/p) for p in ['', 'QtCore', 'QtGui']]
    command += [str(fixture),'/Fe:'+str(work/'benchmark.exe'),'/Fo:'+str(work)+'\\','/link','/LIBPATH:'+str(qt/'lib'),'Qt6Core.lib','Qt6Gui.lib']
    script = work/'build.cmd'
    script.write_text('@echo off\ncall "'+str(find_msvc_developer_environment())+'" -arch=x64 -host_arch=x64 >nul\n'+subprocess.list2cmdline(command)+'\nexit /b %errorlevel%\n',encoding='utf-8')
    subprocess.run(['cmd','/d','/c',str(script)],cwd=work,check=True)
    env = dict(os.environ, QT_QPA_PLATFORM='offscreen', QT_PLUGIN_PATH=str(qt/'plugins'))
    env['PATH']=str(qt/'bin')+os.pathsep+env.get('PATH','')
    print('MODE='+('batched' if batched else 'per-tile'),flush=True)
    subprocess.run([str(work/'benchmark.exe')],cwd=work,env=env,check=True)

if __name__=='__main__': main()
