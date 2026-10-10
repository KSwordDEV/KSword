#pragma once

class QApplication;

// 在调用方已有 QApplication 中验证真实按钮、透明父容器与文件 HEX 外框。
// 不启动主程序、不读取目标文件；返回失败数，详细计数写到标准输出。
int RunPageThemeRegressionFixtures(QApplication& application);
