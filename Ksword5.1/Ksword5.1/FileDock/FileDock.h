#pragma once

// ============================================================
// FileDock.h
// 作用：
// 1) 实现双栏文件资源管理器（左右面板独立）；
// 2) 提供导航、筛选、排序、基础文件操作与右键分析菜单；
// 3) 提供列管理与文件详情窗口入口。
// ============================================================

#include "../Framework.h"
#include "ManualFileSystemParser.h"

#include <QStringList>
#include <QWidget>

#include <cstdint>     // std::uint64_t：文件大小统计。
#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>      // std::vector：导航历史记录容器。

// Qt 前置声明：降低头文件耦合。
class QCheckBox;
class QComboBox;
class QDialog;
class QEvent;
class QFileSystemModel;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QListView;
class QMenu;
class QPlainTextEdit;
class QPushButton;
class QStandardItemModel;
class QStackedWidget;
class QSortFilterProxyModel;
class QSplitter;
class QStatusBar;
class QTabWidget;
class QTableWidget;
class QToolButton;
class QTreeView;
class QVBoxLayout;
class QWidget;

// FileDeleteMode：右键「删除」的权限档位，按“需要的权限强度”从低到高排列。
// - 目录在任何一档都是递归后序删除（子项先删、目录后删），差别只在用什么权限去删；
// - 越靠后的档位越不可逆，UI 必须在确认框里把差别说清楚。
enum class FileDeleteMode
{
    RecycleBin,     // R3 当前权限，移入回收站，可从回收站还原。
    PermanentR3,    // R3 当前权限，递归永久删除，不进回收站。
    ForceR3,        // R3 提权：清属性 + 接管所有权 + 授权完全控制后递归永久删除。
    PendingReboot,  // R3 提权：登记 PendingFileRenameOperations，下次重启时删除。
    DriverR0Native, // R0 驱动：底层 Zw* 方案，保留现有兼容回退。
    DriverR0Irp,    // R0 驱动：IRP_MJ_SET_INFORMATION 穿过完整文件系统栈。
    DriverR0Posix   // R0 驱动：FileDispositionInformationEx POSIX unlink 语义。
};

// ============================================================
// FileDock
// 说明：
// - 左右两栏都用同一套 FilePanelWidgets 结构描述；
// - 每个面板独立维护路径历史、过滤与排序状态。
// ============================================================
class FileDock final : public QWidget
{
    Q_OBJECT

public:
    // 构造函数：
    // - 作用：初始化双栏 UI 并设置默认目录。
    // - 参数 parent：Qt 父控件。
    explicit FileDock(QWidget* parent = nullptr);

    // 析构函数：
    // - 作用：默认析构即可，所有子控件由 Qt 父子关系自动释放。
    ~FileDock() override;

    // openFileDetailByPath：
    // - 作用：对外暴露文件详情窗口入口（含属性/哈希/签名/PE 等 Tab）；
    // - 供 ServiceDock 等模块跨页联动调用。
    // - 参数 filePath：目标文件绝对路径。
    void openFileDetailByPath(const QString& filePath);

    // unlockFileByPath：
    // - 作用：对外暴露“文件解锁器”入口（单路径）；
    // - 供系统右键菜单命令启动后跨页联动调用。
    void unlockFileByPath(const QString& targetPath);

protected:
    // changeEvent：语言切换后立即重绘文件模型的本地化大小/类型文本。
    void changeEvent(QEvent* event) override;

    // eventFilter：
    // - 输入：watched 为被过滤对象，event 为 Qt 事件对象；
    // - 处理：仅拦截文件列表 viewport 的右键按下事件，用于保留多选集合或切换到右键命中的单行；
    // - 返回：事件已由 FileDock 处理时返回 true，否则交回 QWidget 默认实现。
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    // ManualParseBackend：
    // - 作用：把"读取方式"下拉框索引归一为后端类型，避免各调用点各自比较魔法索引；
    // - WindowsApi 走 QFileSystemModel，不进入平铺解析链路。
    enum class ManualParseBackend
    {
        WindowsApi = 0,   // Windows API（QFileSystemModel）。
        ManualFs,         // R3 原始卷手动解析（自动识别或强制 NTFS/FAT32/exFAT）。
        R0Driver,         // R0 ZwQueryDirectoryFile 分页枚举。
        MftStrict,        // 纯 $MFT 扫描，禁用一切 WinAPI/FSCTL 回退。
        R0Irp             // R0 自建 IRP 直发文件系统栈。
    };

    // FilePanelWidgets：
    // - 作用：聚合单个文件面板的全部控件与运行时状态。
    struct FilePanelWidgets
    {
        QWidget* rootWidget = nullptr;         // 面板根容器。
        QVBoxLayout* rootLayout = nullptr;     // 面板主布局。

        QWidget* navWidget = nullptr;          // 导航条容器。
        QHBoxLayout* navLayout = nullptr;      // 导航条布局。
        QPushButton* backButton = nullptr;     // 返回按钮。
        QPushButton* forwardButton = nullptr;  // 前进按钮。
        QPushButton* upButton = nullptr;       // 上级目录按钮。
        QPushButton* refreshButton = nullptr;  // 刷新按钮。
        QStackedWidget* pathStack = nullptr;   // 地址区域堆叠控件（面包屑/编辑框二选一）。
        QLineEdit* pathEdit = nullptr;         // 地址栏输入框（编辑模式）。
        QComboBox* driveCombo = nullptr;       // 地址栏右侧驱动器跳转下拉框。
        QWidget* breadcrumbWidget = nullptr;   // 面包屑容器（展示模式）。
        QHBoxLayout* breadcrumbLayout = nullptr; // 面包屑布局。
        QPushButton* breadcrumbEditTriggerButton = nullptr; // 面包屑末尾空白点击热区。

        QWidget* toolWidget = nullptr;         // 工具条容器。
        QHBoxLayout* toolLayout = nullptr;     // 工具条布局。
        QComboBox* viewModeCombo = nullptr;    // 视图模式选择（图标/列表/详情/树）。
        QCheckBox* showSystemCheck = nullptr;  // 显示系统文件开关。
        QCheckBox* showHiddenCheck = nullptr;  // 显示隐藏文件开关。
        QComboBox* sortModeCombo = nullptr;    // 排序方式选择。
        QComboBox* readModeCombo = nullptr;    // 读取方式（Windows API/R3 手动/R0 驱动/强制 FS）。
        QLineEdit* filterEdit = nullptr;       // 文件名快速过滤输入框。

        QStackedWidget* fileViewStack = nullptr; // 文件视图容器（图标/列表与详情/树之间切换）。
        QListView* compactFileView = nullptr;  // 真正的图标网格/纵向列表视图。
        QTreeView* fileView = nullptr;         // 详情/树形视图，同时持有共享选区。
        QFileSystemModel* fsModel = nullptr;   // 原始文件系统模型。
        QSortFilterProxyModel* proxyModel = nullptr; // 过滤代理模型。
        QStandardItemModel* manualModel = nullptr;   // 手动解析原始模型。
        QSortFilterProxyModel* manualProxyModel = nullptr; // 手动解析代理模型。

        QStatusBar* statusBar = nullptr;       // 面板状态栏。
        QLabel* pathStatusLabel = nullptr;     // 当前路径状态。
        QLabel* selectionStatusLabel = nullptr; // 选中数量/大小状态。
        QLabel* diskStatusLabel = nullptr;     // 磁盘空间状态。
        QLabel* parserStatusLabel = nullptr;   // 当前解析器状态提示。

        std::vector<QString> history;          // 路径历史列表。
        int historyIndex = -1;                 // 当前历史索引。
        QString currentPath;                   // 当前目录路径。
        QString pendingSelectionPath;          // 返回上级后待恢复选中的子目录路径。
        QString manualLoadedPath;              // 手动解析模型当前已加载目录路径。
        QString panelNameText;                 // 面板名称（日志与提示使用）。
        QString lastStatusLogSignature;        // 状态栏日志去重签名。
        QString lastFilterLogSignature;        // 过滤参数日志去重签名。
        bool pathEditMode = false;             // 当前是否处于路径编辑模式。
        ks::file::ManualFsType lastManualFsType = ks::file::ManualFsType::Unknown; // 最近一次手动解析识别到的FS类型。
        ks::file::ManualFsType manualRequestedFsType = ks::file::ManualFsType::Unknown; // 当前读取模式要求的手动解析类型。
        int manualRequestedReadMode = 0;        // 当前模型对应的读取模式索引，防止 R3/R0 结果误复用。
        bool manualResultPartial = false;       // R0 分页/名称边界导致结果不完整时为 true。
        QString manualSourceDetail;             // 当前平铺模型的真实解析来源摘要。
        QStringList manualSuspiciousNames;      // 只有绕过路径可见的条目名（疑似被隐藏）。
        bool manualParseInProgress = false;    // 手动解析后台任务是否正在运行。
        bool manualParsePending = false;       // 手动解析是否有待执行请求。
        bool manualParsePendingShowWarning = false; // 待执行请求是否需要失败弹框。
        int manualParseRequestSerial = 0;      // 手动解析请求序列号（用于丢弃过期结果）。
        QString manualParsingPath;             // 当前后台解析正在处理的路径（用于避免同路径重复解析）。
        int manualParsingReadMode = -1;        // 当前后台解析使用的读取方式索引；同路径换方式必须重解析。
    };

    struct FileOplockAccessRecord;
    struct FileOplockEntry;
    enum class FileOplockLevel
    {
        Level1,
        Level2,
        Batch,
        Filter
    };

    // ======================= UI 初始化 ========================
    // initializeUi：
    // - 作用：构建双栏分割布局并初始化左右面板。
    void initializeUi();

    // initializePanel：
    // - 作用：初始化一个文件面板的全部控件。
    // - 参数 panel：待初始化面板结构体。
    // - 参数 titleText：面板标题文本。
    void initializePanel(FilePanelWidgets& panel, const QString& titleText);

    // initializeConnections：
    // - 作用：绑定单个面板的信号槽交互逻辑。
    // - 参数 panel：目标面板。
    void initializeConnections(FilePanelWidgets& panel);

    // initializeRecoveryPage：
    // - 作用：初始化“文件恢复”竖排 Tab 页面。
    void initializeRecoveryPage();

    // ======================= IRP 构造 =========================
    // initializeIrpBuilderPage：
    // - 作用：初始化“IRP 构造”竖排 Tab 页面，覆盖全部 28 个 IRP_MJ_*。
    void initializeIrpBuilderPage();

    // applyIrpMajorPreset：
    // - 输入：当前选中的 IRP_MJ_* 值；
    // - 处理：按该 major 的定义启用/禁用参数字段并填入常用默认值，
    //   同时对写语义与 PnP/电源类请求打开对应确认开关的要求；
    // - 返回：无返回值。
    void applyIrpMajorPreset(int majorFunction);

    // applyIrpOperationPreset：
    // - 输入：常用操作预设 ID；
    // - 处理：一次性填充 Major、InformationClass、访问权、输入缓冲和目录标志；
    // - 说明：只填参数不发送，写操作仍要求用户显式确认。
    void applyIrpOperationPreset(int presetId);

    // submitConstructedIrp：
    // - 作用：收集页面参数，在后台线程提交一次 R0 自建 IRP，并回填结果；
    // - 说明：写语义与危险 major 在提交前会再次要求用户确认。
    void submitConstructedIrp();

    // updateIrpBuilderEnabledState：
    // - 作用：按后台任务状态统一切换页面控件可用性。
    void updateIrpBuilderEnabledState(bool submitting);

    // irpMajorDisplayText / irpMinorDisplayText：
    // - 作用：把 IRP_MJ_*/IRP_MN_* 数值映射为“数值 + 名称”的下拉文案。
    static QString irpMajorDisplayText(int majorFunction);

    // parseNumericField / parseHexPayload / formatHexDump：
    // - 作用：页面输入解析与输出展示的公共实现；
    // - parseNumericField 同时接受十进制与 0x 前缀十六进制，空串按 0 处理。
    static bool parseNumericField(
        const QString& text,
        unsigned long long& valueOut,
        QString& errorTextOut);
    static bool parseHexPayload(
        const QString& text,
        std::vector<std::uint8_t>& bytesOut,
        QString& errorTextOut);
    static QString formatHexDump(const std::vector<std::uint8_t>& data);

    // ======================= 导航与状态 =======================
    // navigateToPath：
    // - 作用：切换面板目录并可选写入历史。
    // - 参数 panel：目标面板。
    // - 参数 pathText：目标目录路径。
    // - 参数 recordHistory：是否写入导航历史。
    void navigateToPath(FilePanelWidgets& panel, const QString& pathText, bool recordHistory);

    // refreshPanel：
    // - 作用：刷新当前目录并重新应用过滤/排序。
    void refreshPanel(FilePanelWidgets& panel);

    // rebuildBreadcrumb：
    // - 作用：按当前路径重建可点击面包屑。
    void rebuildBreadcrumb(FilePanelWidgets& panel);

    // setPathEditMode：
    // - 作用：切换地址区显示模式（true=编辑框，false=面包屑）。
    void setPathEditMode(FilePanelWidgets& panel, bool editMode);

    // refreshDriveCombo：
    // - 作用：刷新驱动器下拉框列表并同步当前选中项。
    void refreshDriveCombo(FilePanelWidgets& panel);

    // updatePanelStatus：
    // - 作用：更新状态栏（路径、选中数量、容量等）。
    void updatePanelStatus(FilePanelWidgets& panel);

    // selectPendingPath：
    // - 作用：在当前目录模型已经可见后，选中返回上级前所在的子目录；
    // - 说明：Windows API 模型等待 directoryLoaded，手动模型等待异步回填完成。
    void selectPendingPath(FilePanelWidgets& panel);

    // applyPanelFilterAndSort：
    // - 作用：应用显示隐藏文件、名称过滤和排序模式。
    void applyPanelFilterAndSort(FilePanelWidgets& panel);

    // applyReadModeToPanel：
    // - 作用：根据读取模式切换面板模型（Windows API / 自动手动 / 强制文件系统解析）。
    void applyReadModeToPanel(FilePanelWidgets& panel);

    // configureFileViewSelection：
    // - 输入：panel 为需要配置的文件面板；
    // - 处理：统一恢复文件列表的整行多选行为，避免 setModel() 替换 selection model 后退回默认交互；
    // - 返回：无返回值。
    void configureFileViewSelection(FilePanelWidgets& panel);

    // recreateFileSystemModel：
    // - 输入：panel 为需要强制刷新 Windows API 目录数据的面板；
    // - 处理：重建 QFileSystemModel 并重新挂到代理模型，绕开 QFileSystemModel 对 size/mtime 的缓存；
    // - 返回：无返回值。
    void recreateFileSystemModel(FilePanelWidgets& panel);

    // reloadManualModel：
    // - 作用：手动解析当前目录并填充模型。
    // - 参数 showWarningMessage：是否在失败时弹框提示。
    bool reloadManualModel(FilePanelWidgets& panel, bool showWarningMessage);

    // requestAsyncManualReload：
    // - 作用：异步执行手动解析，避免 UI 线程阻塞。
    // - 参数 panel：目标面板。
    // - 参数 showWarningMessage：失败时是否弹框。
    void requestAsyncManualReload(FilePanelWidgets& panel, bool showWarningMessage);

    // currentModeIsManual：
    // - 作用：判断当前面板是否处于手动解析模式。
    bool currentModeIsManual(const FilePanelWidgets& panel) const;

    // currentModeUsesDriver：
    // - 作用：判断平铺目录模型是否应通过 KswordARK 的 R0 目录查询填充。
    bool currentModeUsesDriver(const FilePanelWidgets& panel) const;

    // requestedManualFsTypeForPanel：
    // - 作用：根据读取模式下拉框解析强制文件系统类型；
    // - 返回 Unknown 表示“手动自动识别”。
    ks::file::ManualFsType requestedManualFsTypeForPanel(const FilePanelWidgets& panel) const;

    // manualParseBackendForPanel：
    // - 作用：把读取方式下拉框索引映射为 ManualParseBackend；
    // - 所有平铺解析分派都必须经过本函数，索引与后端的对应关系只维护一处。
    ManualParseBackend manualParseBackendForPanel(const FilePanelWidgets& panel) const;

    // parseBackendIsKernel：
    // - 作用：判断结果是否来自 R0，供状态文案与日志区分 R0/R3 来源。
    static bool parseBackendIsKernel(ManualParseBackend backend);

    // parseBackendDisplayText / parseBackendLogTag：
    // - 作用：为界面提示与结构化日志提供统一的后端名称。
    static QString parseBackendDisplayText(ManualParseBackend backend);
    static const char* parseBackendLogTag(ManualParseBackend backend);

    // runManualParseBackend：
    // - 输入：后端类型、目标路径与强制文件系统类型；
    // - 处理：调用对应解析器，把差异诊断折叠进 sourceDetailOut 供状态栏展示；
    // - 返回：解析成功返回 true，失败时 errorTextOut 含原因。
    // - 说明：本函数只读文件系统与驱动，不触碰任何 UI 对象，可在后台线程调用。
    static bool runManualParseBackend(
        ManualParseBackend backend,
        const QString& pathText,
        ks::file::ManualFsType requestedFsType,
        std::vector<ks::file::ManualDirectoryEntry>& entriesOut,
        ks::file::ManualFsType& fsTypeOut,
        QString& errorTextOut,
        bool& usedWinApiFallbackOut,
        bool& partialOut,
        QString& sourceDetailOut,
        QStringList& suspiciousNamesOut);

    // ======================= 文件操作 =========================
    // showPanelContextMenu：
    // - 作用：显示右键菜单（操作 + 分析子菜单）。
    void showPanelContextMenu(FilePanelWidgets& panel, const QPoint& localPos);

    // openSelectedItems：
    // - 作用：打开当前选中项（支持多选，目录进入或系统打开）。
    void openSelectedItems(FilePanelWidgets& panel);

    // copySelectedItemPath：
    // - 作用：复制选中项完整路径到剪贴板。
    void copySelectedItemPath(FilePanelWidgets& panel);

    // copySelectedItemKernelPath：
    // - 作用：复制选中项的内核命名空间路径（\??\...）到剪贴板。
    void copySelectedItemKernelPath(FilePanelWidgets& panel);

    // copySelectedItemShortName：
    // - 作用：复制选中项短文件名（8.3 名称）到剪贴板。
    void copySelectedItemShortName(FilePanelWidgets& panel);

    // copySelectedItems：
    // - 作用：把当前面板选中项直接复制到对侧面板当前目录。
    void copySelectedItems(FilePanelWidgets& panel);

    // cutSelectedItems：
    // - 作用：把当前面板选中项直接移动到对侧面板当前目录。
    void cutSelectedItems(FilePanelWidgets& panel);

    // oppositePanelFor：
    // - 输入：sourcePanel 为发起复制/剪切动作的源面板；
    // - 处理：根据左右面板实例地址解析对侧面板；
    // - 返回：成功时返回对侧面板指针，无法识别来源时返回 nullptr。
    FilePanelWidgets* oppositePanelFor(FilePanelWidgets& sourcePanel);

    // transferSelectedItemsToOppositePanel：
    // - 输入：sourcePanel 为源面板，moveItems 为 true 时移动、false 时复制；
    // - 处理：读取源面板多选路径，目标固定为对侧面板 currentPath，并逐项复制/移动；
    // - 返回：无返回值，失败项写入日志与进度状态。
    void transferSelectedItemsToOppositePanel(FilePanelWidgets& sourcePanel, bool moveItems);

    // createNewFileOrFolder：
    // - 作用：在当前目录创建新文件或新文件夹。
    void createNewFileOrFolder(FilePanelWidgets& panel, bool createFolder);

    // renameSelectedItem：
    // - 作用：重命名当前选中项。
    void renameSelectedItem(FilePanelWidgets& panel);

    // deleteSelectedItem：
    // - 作用：删除当前选中项，走「移入回收站」这一档（Delete 快捷键入口）。
    void deleteSelectedItem(FilePanelWidgets& panel);

    // deleteSelectedItemByDriver：
    // - 作用：通过 KswordARK 驱动对当前选中项执行递归硬删除。
    // - 说明：新驱动在 R0 内部展开目录树；旧驱动自动回退为 R3 后序展开逐项删除。
    void deleteSelectedItemByDriver(FilePanelWidgets& panel);

    // deleteSelectedItemsWithMode：
    // - 输入：panel 为动作来源面板，mode 为权限档位；
    // - 处理：统一完成前置权限检查、确认文案、后台批量删除与结果汇总；
    //   目录在所有档位都按“子项先删、目录后删”的后序语义处理；
    // - 返回：无返回值，结果通过日志、进度条与消息框反馈。
    void deleteSelectedItemsWithMode(FilePanelWidgets& panel, FileDeleteMode mode);

    // takeOwnershipSelectedItems：
    // - 作用：对当前选中项执行“取得所有权 + 授权完全控制”。
    // - 说明：调用系统 takeown/icacls，失败信息会汇总提示。
    void takeOwnershipSelectedItems(FilePanelWidgets& panel);

    // setSelectedFileIntegrityLevel：
    // - 输入：panel 为右键菜单来源面板，integrityRid 为目标 S-1-16-* Mandatory Label RID；
    // - 处理：R0 内核 API 优先写入文件/目录完整性标签，驱动不可用/旧驱动时回退 R3；
    // - 返回：无返回值，执行结果通过日志和消息框反馈。
    void setSelectedFileIntegrityLevel(
        FilePanelWidgets& panel,
        unsigned long integrityRid,
        const QString& levelDisplayText);

    // unlockSelectedItemsByDriver：
    // - 作用：扫描选中路径占用进程，列出候选进程并按用户选择用 R3/R0 结束；
    // - 说明：用于“文件解锁器”右键动作，不直接删除文件。
    void unlockSelectedItemsByDriver(FilePanelWidgets& panel);

    // addOplockToSelectedFile：
    // - 作用：按指定级别对当前单选文件请求并保持一个 R3 Oplock；
    // - 说明：Oplock 生命周期由 FileDock 维护，直到被触发、手动释放或 FileDock 析构。
    void addOplockToSelectedFile(FilePanelWidgets& panel, FileOplockLevel level);

    // releaseSelectedFileOplock：
    // - 作用：释放当前单选文件上由 FileDock 持有的 Oplock。
    void releaseSelectedFileOplock(FilePanelWidgets& panel);

    // showSelectedFileOplockAccessRecords：
    // - 作用：展示当前单选文件 Oplock 已捕获的访问进程记录。
    void showSelectedFileOplockAccessRecords(FilePanelWidgets& panel);

    // releaseAllActiveOplocks：
    // - 作用：释放 FileDock 当前持有的全部 Oplock。
    // - 参数 showMessage：为 true 时向用户显示释放数量。
    void releaseAllActiveOplocks(bool showMessage);

    // hasActiveOplockForPath / activeOplockCount / activeOplockBreakCountForPath / activeOplockAccessProcessCountForPath：
    // - 作用：查询当前 Oplock 持有和触发计数状态，用于右键菜单启停与展示。
    bool hasActiveOplockForPath(const QString& filePath) const;
    std::size_t activeOplockCount() const;
    std::uint64_t activeOplockBreakCountForPath(const QString& filePath) const;
    std::size_t activeOplockAccessProcessCountForPath(const QString& filePath) const;

    // handleOplockCompleted：
    // - 作用：后台等待线程通知 UI：Oplock 已被访问触发并累计次数。
    void handleOplockCompleted(
        std::shared_ptr<FileOplockEntry> entry,
        bool completionOk,
        unsigned long completionError,
        bool acknowledgeOk,
        unsigned long acknowledgeError,
        std::size_t capturedProcessCount);

    // handleOplockRearmPending：
    // - 作用：后台等待线程通知 UI：触发后重新挂起同级别 Oplock 暂时失败，线程会继续重试。
    void handleOplockRearmPending(std::shared_ptr<FileOplockEntry> entry, unsigned long requestError);

    // fileOplockLevelText / fileOplockControlCode：
    // - 作用：把菜单选择映射到用户可见名称和 Windows FSCTL 请求码。
    static QString fileOplockLevelText(FileOplockLevel level);
    static unsigned long fileOplockControlCode(FileOplockLevel level);

    // requestFileOplock / acknowledgeFileOplockBreak / cancelFileOplockRequest：
    // - 作用：封装 Oplock 异步请求、break ACK 与手动取消，保证计数模式下只在手动释放时关闭句柄。
    static bool requestFileOplock(FileOplockEntry& entry, unsigned long& requestError);
    static bool acknowledgeFileOplockBreak(FileOplockEntry& entry, unsigned long& acknowledgeError);
    static void cancelFileOplockRequest(FileOplockEntry& entry);

    // recordFileOplockAccessPrograms：
    // - 作用：Oplock 被触发后扫描并记录当前访问目标文件的进程候选。
    static std::size_t recordFileOplockAccessPrograms(FileOplockEntry& entry, std::uint64_t breakSequence);

    // unlockPathsByDriver：
    // - 作用：兼容旧“文件解锁器”入口，并统一转交属性窗口的“文件占用与解锁”页；
    // - 该页内提供关闭句柄、R3 结束进程、R0 结束进程，不再存在独立解锁窗口。
    // - 参数 triggerTag / panelForRefresh 保留 ABI，旧调用方无需分叉。
    void unlockPathsByDriver(
        const std::vector<QString>& targetPaths,
        const QString& triggerTag,
        FilePanelWidgets* panelForRefresh);

    // showColumnManagerDialog：
    // - 作用：弹出列管理器切换列显示状态。
    void showColumnManagerDialog(FilePanelWidgets& panel);

    // showFileDetailDialog：
    // - 作用：打开文件详情窗口（多 Tab 信息展示）；initialTabKey 可直达指定页。
    void showFileDetailDialog(const QString& filePath, const QString& initialTabKey = QString());
    void showFileDetailDialog(const QStringList& filePaths, const QString& initialTabKey = QString());

    // openHandleUsageScanWindow：
    // - 作用：兼容原有调用点，打开属性窗口内的统一占用/解锁页；
    // - 不再弹出独立扫描结果窗口。
    // - 参数 scanPaths：待扫描路径集合（文件或目录）。
    void openHandleUsageScanWindow(const std::vector<QString>& scanPaths);

    // openMappedProcessScanWindow：
    // - 作用：基于选中文件打开 R0 Section/ControlArea“映射进程”扫描窗口；
    // - 说明：当前第一版只接受文件，目录会被跳过，失败原因在窗口状态栏展示。
    // - 参数 scanPaths：待扫描文件路径集合。
    void openMappedProcessScanWindow(const std::vector<QString>& scanPaths);

    // ======================= 工具函数 =========================
    // currentIndexPath：
    // - 作用：获取面板当前选中索引对应的绝对路径。
    // - 返回：若无选中则返回空字符串。
    QString currentIndexPath(const FilePanelWidgets& panel) const;

    // selectedPaths：
    // - 作用：获取面板当前多选路径列表。
    std::vector<QString> selectedPaths(const FilePanelWidgets& panel) const;

    // formatSizeText：
    // - 作用：格式化字节大小（B/KB/MB/GB）。
    static QString formatSizeText(std::uint64_t sizeBytes);

    // ======================= 文件恢复 =========================
    // refreshRecoveryVolumeList：
    // - 作用：刷新可扫描卷列表（仅展示 NTFS 卷）。
    void refreshRecoveryVolumeList();

    // scanDeletedFilesForRecovery：
    // - 作用：扫描当前卷的 NTFS 删除项并展示到表格。
    void scanDeletedFilesForRecovery();

    // scanDeletedFilesForRecoveryAsync：
    // - 作用：异步扫描当前卷，避免扫描误删时阻塞 UI。
    void scanDeletedFilesForRecoveryAsync();

    // recoverSelectedDeletedFiles：
    // - 作用：对选中删除项执行恢复（当前支持 resident 数据恢复）。
    void recoverSelectedDeletedFiles();

    // recoverSelectedDeletedFilesAsync：
    // - 作用：异步恢复选中删除项，避免恢复过程阻塞 UI。
    void recoverSelectedDeletedFilesAsync();

    // installRecoveryTableMenu：
    // - 作用：为删除项表格安装右键菜单（复制行 / 文件属性 / 恢复选中）。
    void installRecoveryTableMenu();

    // showDeletedFilePropertiesDialog：
    // - 作用：展示单条删除项的完整取证属性（记录号、序列号、恢复能力等）。
    // - 入参 rowIndex：表格行号，越界时不弹窗。
    void showDeletedFilePropertiesDialog(int rowIndex);

    // applyRecoveryFilter：
    // - 作用：按查找框内容筛选删除项表格，支持子串与正则两种模式；
    // - 说明：只改行可见性，不动缓存顺序，右键与恢复入口的行号映射保持有效。
    void applyRecoveryFilter();

    // updateRecoveryViewState：
    // - 作用：在“空状态引导页”和“结果表格”之间切换。
    // - 入参 hasResults：true 显示表格，false 显示引导页。
    // - 入参 emptyHintText：引导页上的说明文字。
    void updateRecoveryViewState(bool hasResults, const QString& emptyHintText);

private:
    // 根布局控件。
    QVBoxLayout* m_rootLayout = nullptr;       // FileDock 根布局。
    QTabWidget* m_rootTabWidget = nullptr;     // 竖排根 Tab（文件管理 / 文件恢复 / IRP 构造）。
    QWidget* m_fileManagerPage = nullptr;      // 文件管理页容器。
    QWidget* m_fileRecoveryPage = nullptr;     // 文件恢复页容器。
    QWidget* m_irpBuilderPage = nullptr;       // IRP 构造页容器。
    QSplitter* m_mainSplitter = nullptr;       // 左右分栏分割器。

    // IRP 构造页控件。参数字段一律用文本框而不是 spin box：
    // IRP 参数普遍以十六进制常量形式出现在 WDK 文档里，强制十进制输入会让
    // 用户在每次填 CreateOptions/IoControlCode 时都要手工换算。
    QLineEdit* m_irpPathEdit = nullptr;             // 目标 NT/Win32 路径。
    QComboBox* m_irpOperationPresetCombo = nullptr; // 常用操作预设；只填参数、不自动发送。
    QComboBox* m_irpMajorCombo = nullptr;           // IRP_MJ_* 选择。
    QLineEdit* m_irpMinorEdit = nullptr;            // IRP_MN_* 数值。
    QComboBox* m_irpLayerCombo = nullptr;           // 目标栈层。
    QLineEdit* m_irpDesiredAccessEdit = nullptr;    // CREATE：ACCESS_MASK。
    QLineEdit* m_irpShareAccessEdit = nullptr;      // CREATE：共享位。
    QLineEdit* m_irpCreateDispositionEdit = nullptr;// CREATE：处置方式。
    QLineEdit* m_irpCreateOptionsEdit = nullptr;    // CREATE：选项位。
    QLineEdit* m_irpFileAttributesEdit = nullptr;   // CREATE：文件属性。
    QLineEdit* m_irpInformationClassEdit = nullptr; // 各类信息类/电源状态。
    QLineEdit* m_irpControlCodeEdit = nullptr;      // DEVICE_CONTROL / FSCTL 控制码。
    QLineEdit* m_irpSecurityInformationEdit = nullptr; // SECURITY_INFORMATION。
    QLineEdit* m_irpByteOffsetEdit = nullptr;       // READ/WRITE/LOCK 偏移。
    QLineEdit* m_irpLockKeyEdit = nullptr;          // LOCK_CONTROL Key。
    QLineEdit* m_irpLockLengthEdit = nullptr;       // LOCK_CONTROL 长度。
    QLineEdit* m_irpOutputBytesEdit = nullptr;      // 期望输出缓冲长度。
    QLineEdit* m_irpTimeoutEdit = nullptr;          // 等待超时（毫秒）。
    QLineEdit* m_irpPatternEdit = nullptr;          // DIRECTORY_CONTROL 通配符。
    QPlainTextEdit* m_irpInputHexEdit = nullptr;    // 内联输入数据（十六进制）。
    QCheckBox* m_irpConfirmCheck = nullptr;         // 写语义确认。
    QCheckBox* m_irpAllowDangerousCheck = nullptr;  // PnP/电源等危险 major 额外确认。
    QCheckBox* m_irpCreateOnlyCheck = nullptr;      // 只执行 CREATE。
    QCheckBox* m_irpRestartScanCheck = nullptr;     // SL_RESTART_SCAN。
    QCheckBox* m_irpSingleEntryCheck = nullptr;     // SL_RETURN_SINGLE_ENTRY。
    QCheckBox* m_irpReparseCheck = nullptr;         // FILE_OPEN_REPARSE_POINT。
    QCheckBox* m_irpDirectoryIntentCheck = nullptr; // FILE_DIRECTORY_FILE。
    QPushButton* m_irpSendButton = nullptr;         // 发送按钮。
    QLabel* m_irpStatusLabel = nullptr;             // 结果状态摘要。
    QTableWidget* m_irpResultTable = nullptr;       // 各阶段状态与设备栈信息。
    QPlainTextEdit* m_irpOutputHexEdit = nullptr;   // 目标驱动写回的数据。
    bool m_irpSubmitInProgress = false;             // 提交任务是否在运行。

    // 文件恢复页控件。
    QComboBox* m_recoveryVolumeCombo = nullptr; // 恢复卷选择下拉框。
    QPushButton* m_recoveryRefreshButton = nullptr; // 刷新卷按钮。
    QPushButton* m_recoveryScanButton = nullptr;    // 扫描按钮。
    QPushButton* m_recoveryExportButton = nullptr;  // 恢复导出按钮。
    QTableWidget* m_recoveryTable = nullptr;        // 删除项结果表格。
    QLabel* m_recoveryStatusLabel = nullptr;        // 扫描状态标签。
    QLineEdit* m_recoveryFilterEdit = nullptr;      // 结果查找输入框。
    QToolButton* m_recoveryFilterRegexButton = nullptr; // 查找的正则开关。
    QString m_recoveryBaseStatusText;               // 未叠加筛选信息时的扫描统计文案。
    QStackedWidget* m_recoveryViewStack = nullptr;  // 结果区堆叠容器（引导页/结果表格二选一）。
    QWidget* m_recoveryEmptyPage = nullptr;         // 空状态引导页容器。
    QPushButton* m_recoveryEmptyScanButton = nullptr; // 引导页中央扫描按钮。
    QLabel* m_recoveryEmptyHintLabel = nullptr;     // 引导页说明文字。
    std::vector<ks::file::NtfsDeletedFileEntry> m_deletedRecoveryItems; // 删除项缓存（含 resident 数据）。
    bool m_recoveryScanInProgress = false;          // 误删扫描后台任务运行状态。
    bool m_recoveryRecoverInProgress = false;       // 误删恢复后台任务运行状态。

    // 左右面板实例。
    FilePanelWidgets m_leftPanel;              // 左侧面板状态。
    FilePanelWidgets m_rightPanel;             // 右侧面板状态。
    bool m_transferInProgress = false;         // 跨面板复制/移动后台任务是否运行。

    // 文件解锁器后台线程状态。
    std::thread m_unlockerWorkerThread;
    std::atomic_bool m_unlockerWorkerStopRequested{ false };
    std::atomic_bool m_unlockerWorkerRunning{ false };
    mutable std::mutex m_unlockerWorkerMutex;

    // Oplock 持有状态。
    std::vector<std::shared_ptr<FileOplockEntry>> m_activeOplocks;
    mutable std::mutex m_activeOplockMutex;
};
