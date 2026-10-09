// 装配层离屏夹具只检查页面接线，不打开真实插件市场或执行安装事务。
#include "../../../Ksword5.1/Ksword5.1/PluginHost.h"

namespace ks::plugin_host
{
    // showPluginManager：用同签名空宿主替换 UI 路由；生产 C 页与后端仍真实编译。
    void showPluginManager(QWidget*, const QString&)
    {
    }
}
