# zlib 1.3.1

来源：本机已安装的 Qt 6.9.3 源码中附带的 zlib 1.3.1。
版权与许可原文保留在 `zlib.h` 开头，所有源文件原版权说明均保留。

KSword 仅引入解压所需源文件，将 `zlib.h` 的 Qt 导出绑定及版本后缀、
`zconf.h` 的强制 Qt 符号前缀恢复为独立静态库配置，并移除 `zutil.h`、`gzguts.h` 的
Qt 配置头引用。算法未修改。
此库使原生 CLI 无须增加 Qt DLL 依赖即可读取正式 v4 的 qCompress 容器。
