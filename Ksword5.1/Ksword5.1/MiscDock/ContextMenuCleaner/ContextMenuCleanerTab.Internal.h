#pragma once

// ============================================================
// ContextMenuCleanerTab.Internal.h
// 作用：
// 1) 为右键菜单清理页的多个 .cpp 提供共享列定义和注册表 helper 声明；
// 2) 保持 QWidget 页面主头文件只暴露控件类型，不泄漏实现细节；
// 3) 避免单个源文件超过项目约定的长度上限。
// ============================================================

#include <QString>
#include <QStringList>
#include <QVector>

#include <initializer_list>
#include <optional>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace ks::misc::context_menu_cleaner_detail
{
    // 表格列定义：
    // - 输入：所有右键菜单分类表格共用固定列序；
    // - 处理：UI 渲染、筛选、复制和删除都通过这些常量定位列；
    // - 返回：编译期整数常量，无运行时返回值。
    inline constexpr int kColumnName = 0;
    inline constexpr int kColumnDisplayName = 1;
    inline constexpr int kColumnKind = 2;
    inline constexpr int kColumnSource = 3;
    inline constexpr int kColumnCommandOrHandler = 4;
    inline constexpr int kColumnRegistryPath = 5;
    inline constexpr int kColumnStatus = 6;
    inline constexpr int kColumnDetail = 7;
    // 耗时列：放置"逐条差值法"测得的该条贡献（毫秒），未测量时为空。
    // 说明：Shell 不提供单条耗时，这里的数值是"禁用该条后整菜单耗时下降了多少"的差值。
    inline constexpr int kColumnLatency = 8;
    inline constexpr int kColumnCount = 9;

    // RegistryLocationDefinition：
    // - 输入：由枚举逻辑按分类构造；
    // - 处理：描述一个注册表父键及其解析类型；
    // - 返回：普通数据结构，不主动执行逻辑。
    struct RegistryLocationDefinition
    {
        HKEY rootKey = nullptr;       // rootKey：真实根键。
        QString rootLabel;            // rootLabel：显示用根键文本。
        QString subKeyPath;           // subKeyPath：父键路径。
        REGSAM viewFlag = 0;          // viewFlag：WOW64 视图标记。
        QString sourceGroup;          // sourceGroup：来源分类。
        QString entryKind;            // entryKind：shell/shellex/IE MenuExt。
        bool shellVerb = false;       // shellVerb：true 表示子键是 shell verb。
        bool shellExtension = false;  // shellExtension：true 表示子键是 ContextMenuHandlers。
        bool ieMenuExt = false;       // ieMenuExt：true 表示子键是 IE MenuExt。
    };

    // RegistryValueSnapshot：
    // - 输入：由 enumerateRegistryValues 从注册表读取；
    // - 处理：保留值名、显示文本和原始类型，供打开方式等页面精确删除；
    // - 返回：普通数据快照，不持有注册表句柄。
    struct RegistryValueSnapshot
    {
        QString valueName;       // valueName：命名值名称，默认值为空字符串。
        QString valueText;       // valueText：转换后的可读数据。
        DWORD valueType = REG_NONE; // valueType：原始 Win32 注册表类型。
    };

    // buildInputStyle：输入无；处理为筛选框生成主题样式；返回可直接 setStyleSheet 的文本。
    QString buildInputStyle();

    // buildHeaderStyle：输入无；处理为表头生成主题样式；返回可直接 setStyleSheet 的文本。
    QString buildHeaderStyle();

    // queryRegistryValueText：输入注册表位置；处理读取并格式化值；返回文本或 std::nullopt。
    std::optional<QString> queryRegistryValueText(HKEY rootKey, const QString& subKeyPath, const QString& valueName, REGSAM viewFlag);

    // registryValueExists：输入注册表位置；处理只探测值是否存在；返回存在性布尔值。
    bool registryValueExists(HKEY rootKey, const QString& subKeyPath, const QString& valueName, REGSAM viewFlag);

    // enumerateRegistrySubKeys：输入父键位置；处理枚举一级子键；返回排序后的子键名列表。
    QStringList enumerateRegistrySubKeys(HKEY rootKey, const QString& subKeyPath, REGSAM viewFlag);

    // enumerateRegistryValues：输入父键位置；处理枚举当前键的全部值；返回按值名排序的快照。
    QVector<RegistryValueSnapshot> enumerateRegistryValues(HKEY rootKey, const QString& subKeyPath, REGSAM viewFlag);

    // rootPathText：输入显示根键与子键；处理拼接完整路径；返回 UI/剪贴板文本。
    QString rootPathText(const QString& rootLabel, const QString& subKeyPath);

    // registryTargetPathText：输入键和值目标；处理拼接精确删除位置；返回 UI/剪贴板文本。
    QString registryTargetPathText(
        const QString& rootLabel,
        const QString& subKeyPath,
        bool valueTarget,
        const QString& valueName);

    // firstNonEmpty：输入候选文本列表；处理选择第一个非空值；返回非空候选或空字符串。
    QString firstNonEmpty(const std::initializer_list<QString>& values);

    // looksLikeClsid：输入文本；处理粗略识别 {GUID} 外形；返回是否像 CLSID。
    bool looksLikeClsid(const QString& text);

    // queryClsidFriendlyName：输入 CLSID；处理查询 HKCR\CLSID 友好名；返回文本或空字符串。
    QString queryClsidFriendlyName(const QString& clsidText);

    // queryClsidServerPath：输入 CLSID；处理查询 InprocServer32/LocalServer32；返回文本或空字符串。
    QString queryClsidServerPath(const QString& clsidText);

    // appendOptionalDetail：输入详情列表与键值；处理非空值追加；无返回值。
    void appendOptionalDetail(QStringList* detailList, const QString& name, const QString& value);

    // winErrorText：输入 Win32 错误码；处理解析系统错误文本；返回可读错误信息。
    QString winErrorText(DWORD errorCode);

    // deleteRegistryTreeWithView：输入待删注册表子树；处理按指定视图删除；返回成功布尔值并可写错误文本。
    bool deleteRegistryTreeWithView(HKEY rootKey, const QString& subKeyPath, REGSAM viewFlag, QString* errorTextOut);

    // deleteRegistryValueWithView：输入待删注册表值；处理精确删除并可清理 OpenWith MRU；返回成功布尔值。
    bool deleteRegistryValueWithView(
        HKEY rootKey,
        const QString& subKeyPath,
        const QString& valueName,
        REGSAM viewFlag,
        bool cleanupOpenWithMru,
        QString* errorTextOut);

    // addUserAndMachineClassLocations：输入 classes 相对路径；处理追加 HKCU/HKLM 32/64 扫描项；无返回值。
    void addUserAndMachineClassLocations(
        std::vector<RegistryLocationDefinition>* outputList,
        const QString& classesRelativePath,
        const QString& sourceGroup,
        const QString& entryKind,
        bool shellVerb,
        bool shellExtension);

    // addIeMenuExtLocations：输入扫描项数组；处理追加 IE MenuExt 常见位置；无返回值。
    void addIeMenuExtLocations(std::vector<RegistryLocationDefinition>* outputList);

    // addFormatContextMenuLocations：输入扫描项数组；处理追加扩展名/ProgID/SystemFileAssociations 菜单位置；无返回值。
    void addFormatContextMenuLocations(std::vector<RegistryLocationDefinition>* outputList);
}
