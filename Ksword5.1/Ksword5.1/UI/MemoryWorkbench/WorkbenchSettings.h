#pragma once

// ============================================================
// WorkbenchSettings.h
// 作用：
// - 内存工作台要持久化的偏好，键名只在这里定义一次（仿 HexViewSettings.h 的写法：
//   free function + 独立命名空间，不做成持有状态的类）。全部使用应用默认的
//   QSettings 后端，离屏夹具用 QSettings::setPath + setDefaultFormat 重定向。
// - 键名前缀统一 "memwb/workbench/"，与 ux.md 第 9 节的持久化表一一对应。
//
// 失败语义（任何失败都退回默认，绝不让偏好读写影响控件使用）：
// - 读：QSettings 状态非 NoError、键缺失、值类型/内容非法，一律退回默认；
//   列表类偏好（地址历史、隐藏列）在读取时清理空串/重复项/超出上限的尾部。
// - 写：写失败（只读位置、没有组织名）静默忽略，下次读取自然退回默认。
//
// 范围/通道两个持久化键不是本文件的事：会话条当前范围与"每个范围上次使用的
// 通道"由 Core 的 ksword::memwb::ChannelMemory 负责语义，这里只管把它的三个整数
// （进程/内核/物理各一个通道值）与范围整数读写成 QSettings 条目，供装配层
// （WP-J）启动时用 ChannelMemory::Restore 灌入、退出前用 Remember 后的值写回。
// ============================================================

#include <QString>
#include <QStringList>

#include <cstdint>

namespace ks::ui::workbench_settings
{
    // kAddrHistoryLimit：地址历史最多保留的条数（与 ux.md 第 9 节一致）。
    inline constexpr int kAddrHistoryLimit = 20;

    // LoadScope / SaveScope："scope" 键，范围的数值（Scope 枚举），默认 0（进程）。
    std::uint32_t LoadScope();
    void SaveScope(std::uint32_t scope);

    // LoadChannelForScope / SaveChannelForScope："channel/process|kernel|physical" 三个键，
    // scopeValue 越界时读取返回默认（进程 0，内核/物理 1），写入被忽略。
    std::uint32_t LoadChannelForScope(std::uint32_t scopeValue);
    void SaveChannelForScope(std::uint32_t scopeValue, std::uint32_t channelValue);

    // LoadWriteMode / SaveWriteMode："writeMode" 键，0=立即、1=暂存，默认 0。
    std::uint32_t LoadWriteMode();
    void SaveWriteMode(std::uint32_t mode);

    // LoadAddrHistory / SaveAddrHistory："addrHistory" 键，默认空列表。
    QStringList LoadAddrHistory();
    void SaveAddrHistory(const QStringList& history);

    // PushAddrHistory：纯函数，把一条新输入放到历史最前面（同文本去重提到最前，截断到上限）。
    QStringList PushAddrHistory(const QStringList& history, const QString& entry);

    // LoadSidebarVisible / SaveSidebarVisible："sidebarVisible" 键，默认 false。
    bool LoadSidebarVisible();
    void SaveSidebarVisible(bool visible);

    // LoadSidebarWidth / SaveSidebarWidth："sidebarWidth" 键，默认 300，读到非法值退回默认。
    int LoadSidebarWidth();
    void SaveSidebarWidth(int width);

    // LoadSubTab / SaveSubTab："subTab" 键（十六进制/反汇编/文本/对比/C 伪代码，0-4），默认 0。
    int LoadSubTab();
    void SaveSubTab(int subTab);

    // LoadBytesPerRow / SaveBytesPerRow："bytesPerRow" 键，默认 16。
    int LoadBytesPerRow();
    void SaveBytesPerRow(int bytesPerRow);

    // LoadGroupSize / SaveGroupSize："groupSize" 键，默认 1。
    int LoadGroupSize();
    void SaveGroupSize(int groupSize);

    // LoadRowWidthAuto / SaveRowWidthAuto："rowWidthAuto" 键，十六进制页是否按窗口宽度自适应行宽，默认 true。
    // 自适应为真时"bytesPerRow"键保存的是用户上次手动选的值（自适应状态下不会被改写，见 HexPrefs.cpp）。
    bool LoadRowWidthAuto();
    void SaveRowWidthAuto(bool automatic);

    // kHexZoomMin / kHexZoomMax：十六进制画布字号缩放级别的合法范围（含），与 HexCanvas::kMinZoomLevel /
    // kMaxZoomLevel 取同一组数值（本文件不依赖 HexCanvas，所以各存一份，由离屏测试核对两边一致）。
    inline constexpr int kHexZoomMin = -4;
    inline constexpr int kHexZoomMax = 12;

    // LoadHexZoom / SaveHexZoom："hexZoom" 键，字号缩放级别 [kHexZoomMin, kHexZoomMax]，默认 0；
    // 读到范围之外的值（损坏或手改）退回默认 0。
    int LoadHexZoom();
    void SaveHexZoom(int level);

    // LoadLiveRefresh / SaveLiveRefresh："liveRefresh" 键，默认 false。
    bool LoadLiveRefresh();
    void SaveLiveRefresh(bool enabled);

    // LoadLiveIntervalMs / SaveLiveIntervalMs："liveIntervalMs" 键，默认 1000，下限 200ms。
    int LoadLiveIntervalMs();
    void SaveLiveIntervalMs(int intervalMs);

    // LoadAddrBookColumnGroup / SaveAddrBookColumnGroup："addrBook/columnGroup" 键，0=A，默认 0。
    int LoadAddrBookColumnGroup();
    void SaveAddrBookColumnGroup(int columnGroup);

    // LoadAddrBookHiddenColumns / SaveAddrBookHiddenColumns："addrBook/hiddenColumns" 键，默认空。
    QStringList LoadAddrBookHiddenColumns();
    void SaveAddrBookHiddenColumns(const QStringList& hiddenColumns);

    // LoadAddrBookKind / SaveAddrBookKind："addrBook/kind" 键，默认 -1（全部）。
    int LoadAddrBookKind();
    void SaveAddrBookKind(int kind);

    // LoadDiagExpanded / SaveDiagExpanded："diagExpanded" 键，默认 false。
    bool LoadDiagExpanded();
    void SaveDiagExpanded(bool expanded);

    // LoadTextEncoding / SaveTextEncoding："text/encoding" 键，0=ANSI/1=UTF-8/2=UTF-16LE，默认 0。
    int LoadTextEncoding();
    void SaveTextEncoding(int encoding);

}
