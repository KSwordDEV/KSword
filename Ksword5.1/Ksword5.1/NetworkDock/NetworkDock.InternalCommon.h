#pragma once

// ============================================================
// NetworkDock.InternalCommon.h
// 作用：
// 1) 统一 NetworkDock 多个 .cpp 的私有 include；
// 2) 避免每个实现文件重复维护同一批系统/Qt 头；
// 3) 作为拆分后实现文件的“编译上下文基座”。
// ============================================================

#include "NetworkDock.h"
#include "NetworkDock.InternalHelpers.h"

#include "../ProcessDock/ProcessDetailWindow.h"
#include "../UI/MemoryWorkbench/HexView.h"
#include "../UI/TableInteractionSupport.h"
#include "../ksword/network/network_diagnostics_tools.h"
#include "../ksword/network/network_download_tools.h"
#include "../ksword/network/network_format_tools.h"

#include <QAction>
#include <QAbstractItemView>
#include <QCheckBox>
#include <QClipboard>
#include <QColor>
#include <QComboBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QGuiApplication>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QModelIndex>
#include <QProgressBar>
#include <QProcess>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QSizePolicy>
#include <QSpinBox>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QThreadPool>
#include <QTimer>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm> // std::min/std::max：预览长度与范围标准化。
#include <atomic>    // std::atomic_bool：跨线程状态门控。
#include <chrono>    // std::chrono：下载暂停轮询等待的短周期睡眠。
#include <limits>    // std::numeric_limits：包长上限范围表达。
#include <set>       // std::set：表格多选行索引去重。
#include <string>    // std::string：日志桥接文本类型。
#include <thread>    // std::thread：长耗时请求放到后台执行。
#include <unordered_set> // std::unordered_set：ARP接口索引去重。
#include <vector>    // std::vector：批量刷新队列临时容器。

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <IcmpAPI.h>
#include <Iphlpapi.h>
#include <Windns.h>
#include <Ws2tcpip.h>

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Dnsapi.lib")
#pragma comment(lib, "Ws2_32.lib")
