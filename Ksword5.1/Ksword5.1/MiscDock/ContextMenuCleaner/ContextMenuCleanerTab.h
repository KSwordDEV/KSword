#pragma once

// ============================================================
// ContextMenuCleanerTab.h
// 作用：
// 1) 提供“Shell 关联管理”杂项页；
// 2) 展示右键菜单、URL 绑定、文件打开方式和 Explorer 第三方命名空间；
// 3) 支持刷新、筛选、复制注册表位置，并在用户确认后删除选中注册表项目。
// ============================================================

#include "../../Framework.h"

#include <QVector>
#include <QWidget>

#include <atomic>
#include <memory>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QTableWidget;
class QTabWidget;
class QVBoxLayout;
class CodeEditorWidget;

namespace ks::misc
{
    // ContextMenuCleanerTab：
    // - 输入：由 Qt 父控件传入 parent，运行时读取当前系统注册表；
    // - 处理：枚举 Shell 菜单、文件关联和 Explorer 命名空间，填充七个子页表格；
    // - 输出：本控件不返回值，清理动作通过注册表删除、界面刷新与日志反馈结果。
    class ContextMenuCleanerTab final : public QWidget
    {
    public:
        // 构造函数：
        // - 参数 parent：Qt 父控件，可为空；
        // - 处理逻辑：创建七类子 Tab，并立即执行一次注册表枚举；
        // - 返回值：无。
        explicit ContextMenuCleanerTab(QWidget* parent = nullptr);
        ~ContextMenuCleanerTab() override = default;

    private:
        // MenuArea：标识当前操作的右键菜单分区。
        enum class MenuArea
        {
            InternetExplorer, // IE 右键菜单：Internet Explorer MenuExt。
            Desktop,          // 桌面右键菜单：DesktopBackground/Directory Background。
            File,             // 文件右键菜单：*、AllFilesystemObjects、Directory/Folder/Drive。
            UrlBinding,       // URL 绑定：协议注册和当前用户默认协议绑定。
            OpenWith,         // 打开方式：扩展名对应的候选应用与 ProgID。
            FormatMenu,       // 格式右键菜单：扩展名、ProgID 和 SystemFileAssociations。
            ExplorerHome      // 资源管理器主页：第三方或用户注册的 Shell 命名空间。
        };

        // DeleteKind：标识删除整棵注册表子树还是单个注册表值。
        enum class DeleteKind
        {
            RegistryTree, // RegistryTree：删除 subKeyPath 指向的完整子树。
            RegistryValue // RegistryValue：仅删除 subKeyPath 下 valueName 指向的值。
        };

        // ContextMenuEntry：单条右键菜单注册表项快照。
        struct ContextMenuEntry
        {
            MenuArea area = MenuArea::File;       // area：所属子页。
            HKEY rootKey = nullptr;               // rootKey：真实注册表根键，删除时复用。
            QString rootLabel;                    // rootLabel：显示用根键，如 HKCU/HKLM(64位)。
            QString subKeyPath;                   // subKeyPath：待删除的完整子键路径。
            REGSAM viewFlag = 0;                  // viewFlag：WOW64 视图标记，保证枚举/删除同一视图。
            QString sourceGroup;                  // sourceGroup：来源分类，如“文件 *”或“桌面背景”。
            QString entryKind;                    // entryKind：shell/shellex/IE MenuExt。
            QString itemName;                     // itemName：注册表子键名。
            QString displayName;                  // displayName：菜单显示名，缺失时回退子键名。
            QString commandOrHandler;             // commandOrHandler：命令、脚本路径、CLSID 或 COM Server。
            QString clsidText;                    // clsidText：COM 右键处理器 CLSID。
            QString detailText;                   // detailText：状态标记、Icon、AppliesTo 等补充信息。
            QString statusText;                   // statusText：启用/禁用/扩展菜单等状态。
            DeleteKind deleteKind = DeleteKind::RegistryTree; // deleteKind：当前行的精确删除粒度。
            QString valueName;                    // valueName：删除注册表值时使用的命名值。
            bool cleanupOpenWithMru = false;      // cleanupOpenWithMru：删除历史打开方式后同步 MRUList。
            bool canDelete = false;               // canDelete：当前行是否允许从 UI 发起删除。
        };

        // AreaWidgets：每个子页拥有一组独立控件与数据缓存。
        struct AreaWidgets
        {
            QWidget* page = nullptr;              // page：子页根控件。
            QVBoxLayout* layout = nullptr;        // layout：子页根布局。
            QWidget* toolbarWidget = nullptr;     // toolbarWidget：刷新/删除/复制/筛选工具栏。
            QPushButton* refreshButton = nullptr; // refreshButton：刷新当前分类按钮。
            QPushButton* deleteButton = nullptr;  // deleteButton：删除选中项按钮。
            QPushButton* restoreButton = nullptr; // restoreButton：恢复 URL 绑定页上一次删除前的注册表备份。
            QPushButton* copyButton = nullptr;    // copyButton：复制选中注册表路径按钮。
            QLineEdit* filterEdit = nullptr;      // filterEdit：当前分类关键词筛选框。
            QTableWidget* table = nullptr;        // table：右键菜单项列表。
            CodeEditorWidget* detailEditor = nullptr; // detailEditor：本分类的只读详情编辑器，交由详情布局系统托管。
            QLabel* statusLabel = nullptr;        // statusLabel：当前分类统计与提示。
            QVector<ContextMenuEntry> entries;    // entries：当前分类最近一次完整枚举结果。
            bool hasLoaded = false;               // hasLoaded：该分类是否至少完成过一次按需枚举。
        };

    private:
        // initializeUi：
        // - 输入：无；
        // - 处理：创建整体布局、说明文本、七类子页；
        // - 返回：无。
        void initializeUi();

        // createAreaPage：
        // - 输入 area：需要创建的右键菜单分区；
        // - 处理：初始化该分区工具栏、表格、状态栏和信号连接；
        // - 返回：无。
        void createAreaPage(MenuArea area);

        // refreshArea：
        // - 输入 area：目标分区；
        // - 处理：重新枚举该分区注册表项并重建表格；
        // - 返回：无。
        void refreshArea(MenuArea area);

        // rebuildAreaTable：
        // - 输入 area：目标分区；
        // - 处理：按当前筛选文本把缓存 entries 渲染到表格；
        // - 返回：无。
        void rebuildAreaTable(MenuArea area);

        // showAreaContextMenu：
        // - 输入 area：目标分区；localPosition：表格视口内右键坐标；
        // - 处理：弹出复制/删除右键菜单，并执行用户选择；
        // - 返回：无。
        void showAreaContextMenu(MenuArea area, const QPoint& localPosition);

        // deleteSelectedEntries：
        // - 输入 area：目标分区；
        // - 处理：收集表格选中行，确认后删除对应注册表子树并刷新；
        // - 返回：无，失败信息通过 QMessageBox 与日志反馈。
        void deleteSelectedEntries(MenuArea area);

        // isUrlBindingDeletionAllowed：
        // - 输入 entry：准备删除的 URL 绑定快照；
        // - 处理：放行 HKCU 精确协议/UserChoice，以及未命中系统保护规则的 HKLM 第三方协议；
        // - 返回：通过不可绕过的执行时安全边界返回 true。
        static bool isUrlBindingDeletionAllowed(const ContextMenuEntry& entry);

        // isProtectedUrlBindingEntry：
        // - 输入 entry：URL 协议注册快照；
        // - 处理：识别已知 Windows 协议、NoRemove、DelegateExecute 与 Packaged COM 标记；
        // - 返回：属于系统/封装协议且必须避免误删时返回 true。
        static bool isProtectedUrlBindingEntry(const ContextMenuEntry& entry);

        // createUrlBindingBackup：
        // - 输入 entryIndexes：即将删除的 URL 绑定条目下标；
        // - 处理：把完整注册表树复制到当前用户 KSword 备份区并原子切换“最近备份”；
        // - 返回：全部备份成功返回 true，否则返回 false 并写错误文本。
        bool createUrlBindingBackup(const QVector<int>& entryIndexes, QString* errorTextOut) const;

        // restoreLastUrlBindingBackup：
        // - 输入：无；
        // - 处理：验证备份元数据后把最近一次 URL 绑定删除批次复制回原位置；
        // - 返回：无，结果通过界面和日志反馈。
        void restoreLastUrlBindingBackup();

        // copySelectedEntries：
        // - 输入 area：目标分区；
        // - 处理：把选中行的注册表路径复制到剪贴板；
        // - 返回：无。
        void copySelectedEntries(MenuArea area) const;

        // updateAreaDetail：
        // - 输入 area：目标分区；
        // - 处理：读取该分类表格的当前行，按 Qt::UserRole 映射回 entries 下标，
        //   把该条目的完整信息写进本分类的只读详情编辑器；
        //   详情布局宿主（DetailLayoutHost）随后把编辑器文本镜像到当前布局方案里；
        // - 返回：无。无选中行时写入引导占位文本。
        void updateAreaDetail(MenuArea area);

        // buildEntryDetailText：
        // - 输入 entry：单条 Shell 关联快照；
        // - 处理：**只用枚举阶段已采集的字段**拼装详情文本，
        //   其中 CLSID 友好名与服务器路径复用 Internal.h 里既有的 HKCR 查询 helper；
        // - 返回：可直接给只读编辑器显示的多行文本。
        QString buildEntryDetailText(const ContextMenuEntry& entry) const;

        // applyAreaDetailPlaceholder：
        // - 输入 area：目标分区；
        // - 处理：把该分类的引导文本写进详情编辑器（尚未刷新或未选中任何行时使用）；
        // - 返回：无。
        void applyAreaDetailPlaceholder(MenuArea area);

        // ===================== 完整备份 / 恢复（防崩溃兜底）=====================
        // 背景：右键菜单注册表散布在多个根键与 32/64 视图下。一旦本程序在测量过程中
        // 异常退出，就可能留下"临时禁用"的覆盖项，用户会看到菜单残缺。
        // 所以：① 开始测量前自动整份导出；② 恢复备份前也先把当前状态整份导出（加时间戳），
        // 因为"恢复备份"本身也是遗弃当前状态。

        // contextMenuBackupDirectory：
        // - 输入：无；
        // - 处理：返回备份目录（优先 exe 同级 ContextMenuBackups；不可写时回落
        //   %LOCALAPPDATA%\Ksword\ContextMenuBackups）；
        // - 返回：目录绝对路径（可能尚未创建）。
        QString contextMenuBackupDirectory() const;

        // exportContextMenuBackupToFile：
        // - 输入 filePathOut/errorTextOut：可为空；
        // - 处理：把本页覆盖的全部菜单注册表位置递归导出为 JSON（含根键与 32/64 视图）；
        // - 返回：成功返回 true 并写回文件路径；失败返回 false 并写回原因。
        bool exportContextMenuBackupToFile(QString* filePathOut, QString* errorTextOut) const;

        // backupContextMenuToFile：
        // - 输入 showSuccessMessage：true 时弹窗提示路径（按钮触发），false 只写日志（自动备份）；
        // - 处理：调用导出并反馈结果；
        // - 返回：成功返回导出文件路径，失败返回空字符串。
        QString backupContextMenuToFile(bool showSuccessMessage);

        // restoreContextMenuFromFile：
        // - 输入：无（内部弹文件选择框，默认目录为备份目录）；
        // - 处理：① 先把当前状态整份导出（时间戳 + -before-restore）；② 二次确认并列将写回/将删除数量；
        //   ③ 按备份覆盖写回并删除当前多出的键；④ 刷新全部子页；
        // - 返回：无，结果通过弹窗与日志反馈。
        void restoreContextMenuFromFile();

        // ===================== 耗时测量（逐条差值法）=====================

        // LatencyProbeItem：传给后台线程的单条待测项。
        // 说明：只带纯数据，避免后台线程访问 UI 侧容器与 Qt 控件。
        struct LatencyProbeItem
        {
            int entryIndex = -1;      // entryIndex：在 entries 中的下标。
            QString itemName;         // itemName：注册表子键名。
            QString displayName;      // displayName：菜单显示名。
            QString subKeyPath;       // subKeyPath：相对 HKCU 的覆盖路径（HKCU\Software\Classes\... 形式）。
            QString kind;             // kind：shell / shellex / IE MenuExt。
            bool isHandler = false;   // isHandler：true=处理器（改默认值置空），false=verb（加 LegacyDisable）。
            // aliasPaths：与本条指向**同一个扩展**的全部注册项路径（含自身）。
            // 同一个 CLSID 常被注册到多个位置（例如同时挂在 Directory\Background 与 DesktopBackground），
            // 只禁用其中一处，另一处仍会加载并照样慢，差值就会被算成 0 —— 必须整组一起禁用。
            QStringList aliasPaths;
        };

        // currentArea：
        // - 输入：无；
        // - 处理：把当前选中的子页签映射回 MenuArea；
        // - 返回：当前分类（越界时回退到文件右键菜单）。
        MenuArea currentArea() const;

        // areaSupportsLatencyProbe：
        // - 输入 area：目标分类；
        // - 处理：判断该分类是否对应"真实可程序化触发的右键菜单"
        //   （URL 绑定 / 打开方式 / 资源管理器主页不是菜单，无耗时可言）；
        // - 返回：可测量返回 true。
        static bool areaSupportsLatencyProbe(MenuArea area);

        // collectLatencyProbeItems：
        // - 输入 area：目标分类；
        // - 处理：从该分类的 entries 里筛出"可临时禁用"的项（shellex 处理器优先），并算出 HKCU 覆盖路径；
        // - 返回：待测项数组（已按上限截断，超出的项数写进 truncatedCountOut）。
        QVector<LatencyProbeItem> collectLatencyProbeItems(MenuArea area, int* truncatedCountOut) const;

        // startLatencyMeasurement / cancelLatencyMeasurement：
        // - 输入：无；
        // - 处理：启动后台测量（基准 + 逐条临时禁用复测），或请求停止
        //   （kProgress 没有取消接口，长任务必须自带停止标志）；
        // - 返回：无。
        void startLatencyMeasurement();
        void cancelLatencyMeasurement();

        // applyLatencyResults：
        // - 输入 area：目标分类；baselineMs：基准耗时；perEntryMs：与 entries 等长的逐条贡献
        //   （<0 表示该条未测，0 表示"很短"）；report：完整报告文本；
        // - 处理：写耗时列（超过门限标红）、把报告写进详情编辑器、刷新状态栏；
        // - 返回：无。
        void applyLatencyResults(MenuArea area, double baselineMs, const QVector<double>& perEntryMs,
                                 const QString& report);

        // applySingleLatencyResult：
        // - 输入 area：目标分类；entryIndex：entries 下标；valueMs：该条的贡献（0 表示很短）；
        // - 处理：**只更新这一行**的耗时单元格 —— 用于"测完一条立刻填一条"，
        //   让用户不必等整轮跑完才看到结果；
        // - 返回：无。后台线程通过队列调用，按 Qt::UserRole 定位行，筛选/排序后依然正确。
        void applySingleLatencyResult(MenuArea area, int entryIndex, double valueMs);

        // writeLatencyCell：
        // - 输入 widgets：目标分类控件组；row：表格行号；valueMs：贡献值（0=很短）；
        // - 处理：把数值写进耗时列并套用标红/灰色的显示规则（单条更新与整表更新共用同一套规则）；
        // - 返回：无。
        void writeLatencyCell(AreaWidgets* widgets, int row, double valueMs) const;

        // clearLatencyColumn：
        // - 输入 area：目标分类；
        // - 处理：清空该分类的耗时列（重新枚举/筛选重建时调用）；
        // - 返回：无。
        void clearLatencyColumn(MenuArea area);

        // setLatencyUiRunning：
        // - 输入 running：是否正在测量；
        // - 处理：切换"测量/停止"按钮可用性与状态栏文案；
        // - 返回：无。
        void setLatencyUiRunning(bool running);

        // enumerateEntriesForArea：
        // - 输入 area：目标分区；
        // - 处理：按分区分派到右键菜单、关联或命名空间枚举器；
        // - 返回：该分区当前可见的注册表项快照。
        QVector<ContextMenuEntry> enumerateEntriesForArea(MenuArea area) const;

        // enumerateUrlBindingEntries：
        // - 输入：无；
        // - 处理：枚举 URL Protocol 注册和当前用户 UrlAssociations\UserChoice；
        // - 返回：URL 绑定页的注册表项目快照。
        QVector<ContextMenuEntry> enumerateUrlBindingEntries() const;

        // enumerateOpenWithEntries：
        // - 输入：无；
        // - 处理：枚举 Explorer 历史打开方式与 Classes 下候选处理器；
        // - 返回：打开方式页的注册表值或子树快照。
        QVector<ContextMenuEntry> enumerateOpenWithEntries() const;

        // enumerateExplorerHomeEntries：
        // - 输入：无；
        // - 处理：枚举 Explorer Desktop/MyComputer/HomeFolder 中的第三方命名空间；
        // - 返回：资源管理器主页第三方程序项目快照。
        QVector<ContextMenuEntry> enumerateExplorerHomeEntries() const;

        // selectedEntryIndexes：
        // - 输入 area：目标分区；
        // - 处理：读取表格选中行绑定的 entries 下标，自动去重；
        // - 返回：选中的 entries 下标数组。
        QVector<int> selectedEntryIndexes(MenuArea area) const;

        // widgetsForArea：
        // - 输入 area：目标分区；
        // - 处理：返回该分区控件组指针；
        // - 返回：AreaWidgets 指针，area 有效时永不为空。
        AreaWidgets* widgetsForArea(MenuArea area);
        const AreaWidgets* widgetsForArea(MenuArea area) const;

        // areaTitle：
        // - 输入 area：目标分区；
        // - 处理：转换为中文页签标题；
        // - 返回：用于 Tab 与日志的标题文本。
        static QString areaTitle(MenuArea area);

        // areaIconPath：
        // - 输入 area：目标分区；
        // - 处理：按分区选择现有 qrc 图标；
        // - 返回：图标资源路径。
        static QString areaIconPath(MenuArea area);

    private:
        QVBoxLayout* m_rootLayout = nullptr;   // m_rootLayout：本页根布局。
        QTabWidget* m_areaTabWidget = nullptr; // m_areaTabWidget：七类 Shell 关联子 Tab 容器。

        // ===================== 页面级工具栏（备份 / 恢复 / 耗时测量） =====================
        QWidget* m_pageToolbar = nullptr;              // m_pageToolbar：子 Tab 上方的页面级工具栏。
        QPushButton* m_backupButton = nullptr;         // m_backupButton：导出整份右键菜单备份。
        QPushButton* m_restoreBackupButton = nullptr;  // m_restoreBackupButton：从备份文件恢复。
        QPushButton* m_latencyButton = nullptr;        // m_latencyButton：开始测量当前分类耗时。
        QPushButton* m_latencyStopButton = nullptr;    // m_latencyStopButton：请求停止测量。
        QLabel* m_latencyStatusLabel = nullptr;        // m_latencyStatusLabel：测量状态与摘要。

        // ===================== 耗时测量运行状态 =====================
        std::atomic<bool> m_latencyRunning{ false };            // m_latencyRunning：是否有测量任务在跑。
        std::atomic<bool> m_latencyCancelRequested{ false };    // m_latencyCancelRequested：停止标志。
        int m_latencyProgressPid = 0;                           // m_latencyProgressPid：kProgress 任务 PID。
        AreaWidgets m_ieWidgets;               // m_ieWidgets：IE 右键菜单子页控件组。
        AreaWidgets m_desktopWidgets;          // m_desktopWidgets：桌面右键菜单子页控件组。
        AreaWidgets m_fileWidgets;             // m_fileWidgets：文件右键菜单子页控件组。
        AreaWidgets m_urlBindingWidgets;        // m_urlBindingWidgets：URL 绑定子页控件组。
        AreaWidgets m_openWithWidgets;          // m_openWithWidgets：文件打开方式子页控件组。
        AreaWidgets m_formatMenuWidgets;        // m_formatMenuWidgets：格式右键菜单子页控件组。
        AreaWidgets m_explorerHomeWidgets;      // m_explorerHomeWidgets：Explorer 主页第三方程序子页控件组。
    };
}
