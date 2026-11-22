#pragma once

class QWidget;
struct ThreadStackTarget;

// 从线程调用栈打开独立的转储展开窗口；只读本地证据文件。
void ShowKernelDumpStackWindow(QWidget* parent, const ThreadStackTarget& target);
