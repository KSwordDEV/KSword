#include "Framework.h"
#include "registry_workbench_mock.h"
#include "RegistryDock/RegistryOptimizationPage.h"
#include "ArkDriverClient/ArkDriverClient.h"
#include "UI/TableInteractionSupport.h"
#include "RegistryDock/RegistryAdvancedDialogs.h"
#include "RegistryDock/RegistryDocument.h"
#include "RegistryDock/RegistryDocumentApply.h"
#include "RegistryDock/RegistryAccessApplyBackend.h"
#include "RegistryDock/RegistryValueTransactions.h"
#include <QMap>
#include <QSet>
#include <cstring>

namespace registry_ui
{
    std::atomic_bool driverEnabled{false};
    std::atomic_int reads{0}, writes{0}, blockedReads{0};
    std::atomic_int win32KeyRenames{0}, r0KeyRenames{0};
    std::mutex modelMutex;
    std::condition_variable readGate;
    bool holdReads = false;
    QMap<QString,QMap<QString,RegistryValueState>> models;
    QString normalized(QString path)
    {
        if (path.startsWith(QStringLiteral("HKCU\\"),Qt::CaseInsensitive)) path.replace(0,4,QStringLiteral("HKEY_CURRENT_USER"));
        return path.toCaseFolded();
    }
    QString identity(const QString& path,int view) { return QString::number(view) + QLatin1Char(':') + normalized(path); }
    void set(const QString& path,const QString& name,quint32 type,const QByteArray& data,int view)
    {
        std::lock_guard<std::mutex> lock(modelMutex);
        RegistryValueState value{name,type,data,true,true,static_cast<quint32>(data.size())};
        models[identity(path,view)][name.toCaseFolded()] = value;
    }
    RegistryValueState get(const QString& path,const QString& name,int view)
    {
        std::lock_guard<std::mutex> lock(modelMutex);
        const auto key = models.constFind(identity(path,view));
        if (key == models.cend()) return RegistryValueState{name};
        auto value = key->value(name.toCaseFolded(),RegistryValueState{name});
        value.name = name;
        return value;
    }
    void blockReads(bool block)
    {
        { std::lock_guard<std::mutex> lock(modelMutex); holdReads = block; }
        if (!block) readGate.notify_all();
    }
    void seed()
    {
        { std::lock_guard<std::mutex> lock(modelMutex); models.clear(); holdReads=false; }
        reads=0; writes=0; blockedReads=0; driverEnabled=false;
        win32KeyRenames = 0;
        r0KeyRenames = 0;
        for (int view : {0,32,64})
        {
            set(QStringLiteral("HKEY_CURRENT_USER"),QStringLiteral("RootMarker"),REG_SZ,QByteArray("R\0\0\0",4),view);
            set(QStringLiteral("HKCU\\Console"),QStringLiteral("ColorTable12"),REG_DWORD,QByteArray("\x12\x34\x56\0",4),view);
            set(QStringLiteral("HKCU\\Console"),QStringLiteral("Text"),REG_SZ,QByteArray("O\0l\0d\0\0\0",8),view);
            set(QStringLiteral("HKCU\\Console"),QStringLiteral("Qword"),REG_QWORD,QByteArray(8,char(0xff)),view);
            set(QStringLiteral("HKCU\\Console"),QStringLiteral("Blob"),REG_BINARY,QByteArray(8192,char(0x59)),view);
            set(QStringLiteral("HKCU\\Console"),QString(),REG_SZ,QByteArray("D\0\0\0",4),view);
            set(QStringLiteral("HKCU\\Environment"),QStringLiteral("Other"),REG_SZ,QByteArray("E\0\0\0",4),view);
            if (view==32) set(QStringLiteral("HKCU\\Console"),QStringLiteral("ViewOnly32"),REG_DWORD,QByteArray(4,'\0'),view);
        }
    }
}

bool RegistryWorkbenchAccess::read(const QString& path,const QString& name,const RegistryAccessContext& context,RegistryValueState* state,QString* error)
{
    ++registry_ui::reads;
    auto snapshot = registry_ui::get(path,name,context.viewBits);
    {
        std::unique_lock<std::mutex> lock(registry_ui::modelMutex);
        if (registry_ui::holdReads) { ++registry_ui::blockedReads; registry_ui::readGate.wait(lock,[]{return !registry_ui::holdReads;}); }
    }
    if (state) *state=snapshot;
    if (error) error->clear();
    return true;
}
bool RegistryWorkbenchAccess::enumerate(const QString& path,const RegistryAccessContext& context,RegistryKeyListing* listing,QString* error,bool includeSubkeys)
{
    RegistryKeyListing result;
    std::lock_guard<std::mutex> lock(registry_ui::modelMutex);
    const QString root = registry_ui::identity(path,context.viewBits);
    const auto key = registry_ui::models.constFind(root);
    if (key!=registry_ui::models.cend())
        for (const auto& value : *key) result.values.push_back(value);
    if (includeSubkeys)
    {
        const QString prefix=root+QLatin1Char('\\');
        QSet<QString> names;
        for (auto it=registry_ui::models.cbegin();it!=registry_ui::models.cend();++it)
            if (it.key().startsWith(prefix)) names.insert(it.key().mid(prefix.size()).section(QLatin1Char('\\'),0,0));
        result.subKeys=QStringList(names.cbegin(),names.cend());
        result.subKeys.sort();
    }
    if (listing) *listing=result;
    if (error) error->clear();
    return true;
}
bool RegistryWorkbenchAccess::write(const QString& path,const RegistryValueState& value,const RegistryAccessContext& context,QString* error)
{
    ++registry_ui::writes;
    registry_ui::set(path,value.name,value.type,value.data,context.viewBits);
    if (error) error->clear();
    return true;
}
bool RegistryWorkbenchAccess::removeValue(const QString& path,const QString& name,const RegistryAccessContext& context,QString* error)
{
    ++registry_ui::writes;
    std::lock_guard<std::mutex> lock(registry_ui::modelMutex);
    registry_ui::models[registry_ui::identity(path,context.viewBits)].remove(name.toCaseFolded());
    if(error)error->clear(); return true;
}
bool RegistryWorkbenchAccess::createKey(const QString&,const RegistryAccessContext&,QString* error) { if(error)*error=QStringLiteral("Fixture refuses key mutation"); return false; }
// 完整 Dock 夹具也只模拟共享访问边界，不再测试已经删除的私有 rename helper。
bool RegistryWorkbenchAccess::keyExists(const QString& path,const RegistryAccessContext& context,bool* exists,QString* error)
{
    std::lock_guard<std::mutex> lock(registry_ui::modelMutex);
    if (exists) *exists=registry_ui::models.contains(registry_ui::identity(path,context.viewBits));
    if (error) error->clear();
    return true;
}
bool RegistryWorkbenchAccess::renameKey(const QString& path,const QString& name,const RegistryAccessContext& context,QString* output,QString* error)
{
    std::lock_guard<std::mutex> lock(registry_ui::modelMutex);
    const QString target=path.left(path.lastIndexOf(QLatin1Char('\\'))+1)+name;
    const QString sourceIdentity=registry_ui::identity(path,context.viewBits);
    const QString targetIdentity=registry_ui::identity(target,context.viewBits);
    if (!registry_ui::models.contains(sourceIdentity)||registry_ui::models.contains(targetIdentity))
    {
        if(error)*error=QStringLiteral("Mock source missing or destination exists");
        return false;
    }
    if(context.useR0)++registry_ui::r0KeyRenames;else ++registry_ui::win32KeyRenames;
    registry_ui::models[targetIdentity]=registry_ui::models.take(sourceIdentity);
    if(output)*output=target;
    if(error)error->clear();
    return true;
}
QString RegistryWorkbenchAccess::kernelPath(const QString& path)
{
    // 与生产通道边界一致：HKCR 合并视图不存在可表示它的单一内核路径。
    if (path.compare(QStringLiteral("HKEY_CLASSES_ROOT"), Qt::CaseInsensitive) == 0
        || path.startsWith(QStringLiteral("HKEY_CLASSES_ROOT\\"), Qt::CaseInsensitive))
        return {};
    return QStringLiteral("\\REGISTRY\\USER\\MOCK") + path.mid(path.indexOf(QLatin1Char('\\')));
}

namespace {
    struct FakeKey { QString path; int view; };
    QString rootPath(HKEY key)
    {
        if(key==HKEY_CURRENT_USER)return QStringLiteral("HKEY_CURRENT_USER");
        if(key==HKEY_LOCAL_MACHINE)return QStringLiteral("HKEY_LOCAL_MACHINE");
        if(key==HKEY_CLASSES_ROOT)return QStringLiteral("HKEY_CLASSES_ROOT");
        if(key==HKEY_USERS)return QStringLiteral("HKEY_USERS");
        if(key==HKEY_CURRENT_CONFIG)return QStringLiteral("HKEY_CURRENT_CONFIG");
        return reinterpret_cast<FakeKey*>(key)->path;
    }
    bool predefined(HKEY key) { return key==HKEY_CURRENT_USER||key==HKEY_LOCAL_MACHINE||key==HKEY_CLASSES_ROOT||key==HKEY_USERS||key==HKEY_CURRENT_CONFIG; }
}
LSTATUS WINAPI RegistryUiRegOpenKeyExW(HKEY root,LPCWSTR sub,DWORD,REGSAM access,PHKEY out)
{
    QString path=rootPath(root); const QString name=sub?QString::fromWCharArray(sub):QString();
    if(!name.isEmpty())path+=QLatin1Char('\\')+name;
    const int view=(access&KEY_WOW64_32KEY)?32:(access&KEY_WOW64_64KEY)?64:predefined(root)?0:reinterpret_cast<FakeKey*>(root)->view;
    *out=reinterpret_cast<HKEY>(new FakeKey{path,view}); return ERROR_SUCCESS;
}
LSTATUS WINAPI RegistryUiRegCloseKey(HKEY key) { if(key&&!predefined(key))delete reinterpret_cast<FakeKey*>(key); return ERROR_SUCCESS; }
LSTATUS WINAPI RegistryUiRegEnumKeyExW(HKEY key,DWORD index,LPWSTR buffer,LPDWORD size,LPDWORD,LPWSTR,LPDWORD,PFILETIME)
{
    auto* handle=reinterpret_cast<FakeKey*>(key); RegistryKeyListing listing; QString error;
    RegistryWorkbenchAccess::enumerate(handle->path,{handle->view,false},&listing,&error,true);
    if(index>=static_cast<DWORD>(listing.subKeys.size()))return ERROR_NO_MORE_ITEMS;
    const std::wstring name=listing.subKeys[index].toStdWString();
    if(*size<=name.size()){*size=static_cast<DWORD>(name.size()+1);return ERROR_MORE_DATA;}
    std::copy(name.cbegin(),name.cend(),buffer);buffer[name.size()]=0;*size=static_cast<DWORD>(name.size()); return ERROR_SUCCESS;
}
LSTATUS WINAPI RegistryUiRegQueryValueExW(HKEY key,LPCWSTR name,LPDWORD,LPDWORD type,LPBYTE data,LPDWORD size)
{
    auto* handle=reinterpret_cast<FakeKey*>(key); const auto value=registry_ui::get(handle->path,QString::fromWCharArray(name?name:L""),handle->view);
    if(!value.exists)return ERROR_FILE_NOT_FOUND;
    if(type)*type=value.type;
    const DWORD required=static_cast<DWORD>(value.data.size());
    if(!data){*size=required;return ERROR_SUCCESS;}
    if(*size<required){*size=required;return ERROR_MORE_DATA;}
    std::copy(value.data.cbegin(),value.data.cend(),data);*size=required;return ERROR_SUCCESS;
}
LSTATUS WINAPI RegistryUiRegSetValueExW(HKEY key,LPCWSTR name,DWORD,DWORD type,const BYTE* data,DWORD size)
{
    auto* handle=reinterpret_cast<FakeKey*>(key);++registry_ui::writes;
    registry_ui::set(handle->path,QString::fromWCharArray(name?name:L""),type,QByteArray(reinterpret_cast<const char*>(data),size),handle->view);return ERROR_SUCCESS;
}
LSTATUS WINAPI RegistryUiRegRenameKey(HKEY parent, LPCWSTR oldName, LPCWSTR newName)
{
    // 只改夹具内存中的键；不链接或调用真实注册表重命名入口。
    auto* key = reinterpret_cast<FakeKey*>(parent);
    const QString oldPath = key->path + QLatin1Char('\\') + QString::fromWCharArray(oldName);
    const QString newPath = key->path + QLatin1Char('\\') + QString::fromWCharArray(newName);
    const QString oldIdentity = registry_ui::identity(oldPath, key->view);
    const QString newIdentity = registry_ui::identity(newPath, key->view);
    std::lock_guard<std::mutex> lock(registry_ui::modelMutex);
    ++registry_ui::win32KeyRenames;
    if (!registry_ui::models.contains(oldIdentity))
        return ERROR_FILE_NOT_FOUND;
    if (registry_ui::models.contains(newIdentity))
        return ERROR_ALREADY_EXISTS;
    registry_ui::models.insert(newIdentity, registry_ui::models.take(oldIdentity));
    return ERROR_SUCCESS;
}
FARPROC WINAPI RegistryUiGetProcAddress(HMODULE, LPCSTR name)
{
    if (std::strcmp(name, "RegRenameKey") != 0)
        return nullptr;
    const auto function = &RegistryUiRegRenameKey;
    FARPROC result = nullptr;
    static_assert(sizeof(result) == sizeof(function));
    std::memcpy(&result, &function, sizeof(result));
    return result;
}

ksword::ark::RegistryEnumResult ksword::ark::DriverClient::enumerateRegistryKey(const std::wstring& kernel,unsigned long) const
{
    RegistryEnumResult result; result.io.ok=true;result.status=KSWORD_ARK_REGISTRY_ENUM_STATUS_SUCCESS;
    const QString text=QString::fromStdWString(kernel); const qsizetype marker=text.indexOf(QStringLiteral("\\Console"),0,Qt::CaseInsensitive);
    const QString path=marker<0?QStringLiteral("HKEY_CURRENT_USER"):QStringLiteral("HKEY_CURRENT_USER")+text.mid(marker);
    RegistryKeyListing listing;QString error;RegistryWorkbenchAccess::enumerate(path,{0,true},&listing,&error,true);
    for(const auto& name:listing.subKeys)result.subKeys.push_back({name.toStdWString()});
    return result;
}

RegistryOptimizationPage::RegistryOptimizationPage(QWidget* parent):QWidget(parent){}
RegistryOptimizationPage::~RegistryOptimizationPage()=default;
void ShowRegistryKeyPermissions(QWidget*,const QString&,int){}
void ShowRegistryOfflineHive(QWidget*){}

// The document state machine has its own 272-case fixture. The Dock fixture
// refuses these transports so no modal interaction can touch the live registry.
namespace { bool refuseDocument(QString& error) { error=QStringLiteral("Fixture refuses live document transport"); return false; } }
bool RegistryDocumentService::captureWin32(const QString&,int,RegistryDocument&,QString& error,qint64){return refuseDocument(error);}
bool RegistryDocumentService::saveBackup(const QString&,const RegistryDocument&,QString& error){return refuseDocument(error);}
bool RegistryDocumentService::saveRegFile(const QString&,const RegistryDocument&,QString& error){return refuseDocument(error);}
bool RegistryDocumentService::parseRegFile(const QString&,RegistryDocument&,QString& error){return refuseDocument(error);}
bool RegistryDocumentService::loadBackup(const QString&,RegistryDocument&,QString& error){return refuseDocument(error);}
bool RegistryDocumentService::encodeBackup(const RegistryDocument&,QByteArray&,QString& error){return refuseDocument(error);}
bool RegistryDocumentService::decodeBackup(const QByteArray&,RegistryDocument&,QString& error){return refuseDocument(error);}
bool RegistryDocumentApplyService::prepareWin32(const RegistryDocument&,RegistryApplyPlan&,QString& error){return refuseDocument(error);}
bool RegistryDocumentApplyService::applyWin32(const RegistryApplyPlan& plan,RegistryApplyResult& result,const std::atomic_bool* canceled)
{
    RegistryAccessApplyBackend backend({plan.viewBits,false}); // 单值实际执行共享状态机，底层只有内存 map。
    return applyWithBackend(plan,backend,result,canceled);
}
bool RegistryDocumentApplyService::undoWin32(const RegistryApplyResult& previous,RegistryApplyResult& result,const std::atomic_bool* canceled)
{
    RegistryAccessApplyBackend backend({previous.viewBits,false});
    return undoWithBackend(previous,backend,result,canceled);
}
// 只替换 KTM 传输边界，整个值移动持有模型锁，模拟一次真实提交；没有普通逐步补写。
bool RegistryDocumentApplyService::moveValueWin32(const QString& source,const QString& name,
    const QString& destination,const QString& newName,const RegistryApplyValueState& expected,
    const int view,RegistryValueRenameResult& result)
{
    std::lock_guard<std::mutex> lock(registry_ui::modelMutex);
    result={};
    const QString sourceIdentity=registry_ui::identity(source,view);
    const QString destinationIdentity=registry_ui::identity(destination,view);
    const auto before=registry_ui::models.value(sourceIdentity).value(name.toCaseFolded());
    const auto target=registry_ui::models.value(destinationIdentity).value(newName.toCaseFolded());
    result.actualOriginal={before.exists,before.type,before.data};
    result.actualDestination={target.exists,target.type,target.data};
    result.originalVerified=result.destinationVerified=true;
    if(!before.exists||before.type!=expected.type||before.data!=expected.data||target.exists)
    {
        result.error=QStringLiteral("Mock atomic value move conflict");
        return false;
    }
    RegistryValueState moved{newName,expected.type,expected.data,true,true,static_cast<quint32>(expected.data.size())};
    registry_ui::models[destinationIdentity][newName.toCaseFolded()]=moved;
    registry_ui::models[sourceIdentity].remove(name.toCaseFolded());
    registry_ui::writes+=2;
    result.committed=true;
    result.state=RegistryValueRenameResult::State::Renamed;
    result.actualOriginal={};
    result.actualDestination=expected;
    return true;
}

namespace ks::ui {
    bool DeferTableUiCommitIfContextMenuOpen(QObject*,const QString&,const QList<QTableView*>&,std::function<void()>){return false;}
    bool DeferItemViewUiCommitIfContextMenuOpen(QObject*,const QString&,const QList<QAbstractItemView*>&,std::function<void()>){return false;}
    bool IsTableUiCommitBlockedByContextMenu(const QList<QTableView*>&){return false;}
    bool IsItemViewUiCommitBlockedByContextMenu(const QList<QAbstractItemView*>&){return false;}
}
