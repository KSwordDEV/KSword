#include "VirtualLocation.h"
#include "../../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include <windows.foundation.h>
#include <windows.devices.geolocation.h>
#include <roapi.h>
#include <wrl/client.h>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <locale>
#include <sstream>

#pragma comment(lib, "RuntimeObject.lib")

namespace ks::r3::location {
namespace {
const wchar_t* const paths[] = {
    L"SYSTEM\\CurrentControlSet\\Services\\lfsvc\\Service\\Configuration\\DefaultLocation",
    L"SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors"};
const wchar_t* const nativePaths[] = {
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\lfsvc\\Service\\Configuration\\DefaultLocation",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors"};
const wchar_t* const names[] = {L"Latitude",L"Longitude",L"Altitude",L"ErrorRadius",L"AltitudeAccuracy"};
bool missing(DWORD error) {return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;}
constexpr double pi=3.1415926535897932384626, eccentricity=0.00669342162296594323, axis=6378245.0, baidu=pi*3000.0/180.0;
bool outside(double lat,double lon){return lon<72.004||lon>137.8347||lat<0.8293||lat>55.8271;}
void wgsToGcj(double lat,double lon,double& outLat,double& outLon){if(outside(lat,lon)){outLat=lat;outLon=lon;return;}
    double x=lon-105,y=lat-35;
    double a=-100+2*x+3*y+0.2*y*y+0.1*x*y+0.2*std::sqrt(std::fabs(x));
    a+=(20*std::sin(6*x*pi)+20*std::sin(2*x*pi))*2/3;
    a+=(20*std::sin(y*pi)+40*std::sin(y/3*pi))*2/3;
    a+=(160*std::sin(y/12*pi)+320*std::sin(y*pi/30))*2/3;
    double b=300+x+2*y+0.1*x*x+0.1*x*y+0.1*std::sqrt(std::fabs(x));
    b+=(20*std::sin(6*x*pi)+20*std::sin(2*x*pi))*2/3;
    b+=(20*std::sin(x*pi)+40*std::sin(x/3*pi))*2/3;
    b+=(150*std::sin(x/12*pi)+300*std::sin(x/30*pi))*2/3;
    const double rad=lat*pi/180;double magic=std::sin(rad);magic=1-eccentricity*magic*magic;
    const double root=std::sqrt(magic);outLat=lat+(a*180)/((axis*(1-eccentricity))/(magic*root)*pi);
    outLon=lon+(b*180)/(axis/root*std::cos(rad)*pi);
}
Operation driverOp(const ksword::ark::RegistryOperationResult& r) {
    return {r.io.ok && r.status==KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS, r.io.win32Error,r.status,r.lastStatus,r.io.deviceOpenFailed};
}
bool parseNumber(const Value& v, double& out) {
    if (!v.known || !v.present) return false;
    if ((v.type==REG_SZ || v.type==REG_EXPAND_SZ) && v.bytes.size()>=sizeof(wchar_t) && v.bytes.size()%sizeof(wchar_t)==0) {
        std::wstring s(v.bytes.size()/sizeof(wchar_t),L'\0');std::memcpy(s.data(),v.bytes.data(),v.bytes.size());
        const auto nul=s.find(L'\0');if(nul==std::wstring::npos)return false;s.resize(nul);
        std::wistringstream in(s);in.imbue(std::locale::classic());in>>out;if(in.fail())return false;in>>std::ws;return in.eof() && std::isfinite(out);
    }
    if ((v.type==REG_QWORD || v.type==REG_BINARY) && v.bytes.size()==sizeof(double)) {std::memcpy(&out,v.bytes.data(),sizeof(out));return std::isfinite(out);}
    if (v.type==REG_DWORD && v.bytes.size()==sizeof(DWORD)){DWORD n=0;std::memcpy(&n,v.bytes.data(),sizeof(n));out=static_cast<double>(n);return true;}
    return false;
}
std::vector<std::uint8_t> asString(double value) {
    std::wostringstream out;out.imbue(std::locale::classic());out<<std::fixed<<std::setprecision(8)<<value;
    const auto s=out.str();const auto* p=reinterpret_cast<const std::uint8_t*>(s.c_str());
    return {p,p+(s.size()+1)*sizeof(wchar_t)};
}
}
const wchar_t* valueName(std::size_t i) {return i<5?names[i]:L"";}
Coordinate convert(const Coordinate& source,CoordinateSystem from,CoordinateSystem to){Coordinate out=source;if(from==to)return out;
    double lat=source.latitude,lon=source.longitude;if(from==CoordinateSystem::Wgs84)wgsToGcj(lat,lon,lat,lon);
    else if(from==CoordinateSystem::Bd09){const double x=lon-0.0065,y=lat-0.006;const double radius=std::sqrt(x*x+y*y)-0.00002*std::sin(y*baidu);
        const double theta=std::atan2(y,x)-0.000003*std::cos(x*baidu);lon=radius*std::cos(theta);lat=radius*std::sin(theta);}
    if(to==CoordinateSystem::Wgs84){if(outside(lat,lon)){out.latitude=lat;out.longitude=lon;return out;}double guessLat=lat,guessLon=lon;
        for(int i=0;i<12;++i){double a=0,b=0;wgsToGcj(guessLat,guessLon,a,b);const double da=lat-a,db=lon-b;guessLat+=da;guessLon+=db;if(std::fabs(da)<1e-9&&std::fabs(db)<1e-9)break;}
        out.latitude=guessLat;out.longitude=guessLon;
    }else if(to==CoordinateSystem::Bd09){const double radius=std::sqrt(lon*lon+lat*lat)+0.00002*std::sin(lat*baidu);
        const double theta=std::atan2(lat,lon)+0.000003*std::cos(lon*baidu);out.latitude=radius*std::sin(theta)+0.006;out.longitude=radius*std::cos(theta)+0.0065;
    }else{out.latitude=lat;out.longitude=lon;}return out;}
Value readConsent(bool desktop){Value v;std::wstring path=L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location";if(desktop)path+=L"\\NonPackaged";
    HKEY key=nullptr;LSTATUS s=RegOpenKeyExW(HKEY_LOCAL_MACHINE,path.c_str(),0,KEY_QUERY_VALUE|KEY_WOW64_64KEY,&key);
    if(s!=ERROR_SUCCESS){v.win32Error=static_cast<DWORD>(s);v.known=missing(v.win32Error);return v;}
    DWORD count=0,type=0;s=RegQueryValueExW(key,L"Value",nullptr,&type,nullptr,&count);
    if(s==ERROR_SUCCESS&&count<=65536){v.bytes.resize(count);DWORD n=count;s=RegQueryValueExW(key,L"Value",nullptr,&type,v.bytes.empty()?nullptr:v.bytes.data(),&n);v.bytes.resize(s==ERROR_SUCCESS?n:0);}else if(s==ERROR_SUCCESS)s=ERROR_MORE_DATA;
    RegCloseKey(key);v.win32Error=static_cast<DWORD>(s);v.known=s==ERROR_SUCCESS||missing(v.win32Error);v.present=s==ERROR_SUCCESS;v.type=type;return v;}
Value SystemRegistry::read(bool policy,const wchar_t* name) {
    Value v;const auto index=policy?1:0;
    if(driver_) {const auto r=ksword::ark::DriverClient().readRegistryValue(nativePaths[index],name);
        v.win32Error=r.io.win32Error;v.driverStatus=r.status;v.ntStatus=r.lastStatus;v.deviceOpenFailed=r.io.deviceOpenFailed;
        v.known=r.io.ok && (r.status==KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS || r.status==KSWORD_ARK_REGISTRY_READ_STATUS_NOT_FOUND);
        v.present=v.known && r.status==KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS && r.dataBytes==r.requiredBytes && r.data.size()==r.dataBytes;
        if(r.status==KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS && !v.present) v.known=false;
        v.type=r.valueType;v.bytes=r.data;return v;}
    HKEY key=nullptr;LSTATUS s=RegOpenKeyExW(HKEY_LOCAL_MACHINE,paths[index],0,KEY_QUERY_VALUE|KEY_WOW64_64KEY,&key);
    if(s!=ERROR_SUCCESS){v.win32Error=static_cast<DWORD>(s);v.known=missing(v.win32Error);return v;}
    DWORD count=0,type=0;s=RegQueryValueExW(key,name,nullptr,&type,nullptr,&count);
    if(s==ERROR_SUCCESS && count<=65536){v.bytes.resize(count);DWORD n=count;s=RegQueryValueExW(key,name,nullptr,&type,v.bytes.empty()?nullptr:v.bytes.data(),&n);v.bytes.resize(s==ERROR_SUCCESS?n:0);}
    else if(s==ERROR_SUCCESS) s=ERROR_MORE_DATA;
    RegCloseKey(key);v.win32Error=static_cast<DWORD>(s);v.known=s==ERROR_SUCCESS||missing(v.win32Error);v.present=s==ERROR_SUCCESS;v.type=type;return v;
}
Operation SystemRegistry::write(bool policy,const wchar_t* name,DWORD type,const std::vector<std::uint8_t>& data) {
    const auto i=policy?1:0;if(driver_){ksword::ark::DriverClient c;const auto create=c.createRegistryKey(nativePaths[i]);
        if(!create.io.ok||(create.status!=KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS && create.status!=KSWORD_ARK_REGISTRY_OPERATION_STATUS_ALREADY_EXISTS))return driverOp(create);
        return driverOp(c.setRegistryValue(nativePaths[i],name,type,data));}
    HKEY key=nullptr;DWORD disposition=0;LSTATUS s=RegCreateKeyExW(HKEY_LOCAL_MACHINE,paths[i],0,nullptr,0,KEY_SET_VALUE|KEY_WOW64_64KEY,nullptr,&key,&disposition);
    if(s==ERROR_SUCCESS){s=RegSetValueExW(key,name,0,type,data.data(),static_cast<DWORD>(data.size()));RegCloseKey(key);}return {s==ERROR_SUCCESS,static_cast<DWORD>(s),0,0};
}
Operation SystemRegistry::remove(bool policy,const wchar_t* name) {
    const auto i=policy?1:0;if(driver_){const auto r=ksword::ark::DriverClient().deleteRegistryValue(nativePaths[i],name);auto o=driverOp(r);if(r.io.ok && r.status==KSWORD_ARK_REGISTRY_OPERATION_STATUS_NOT_FOUND)o.success=true;return o;}
    HKEY key=nullptr;LSTATUS s=RegOpenKeyExW(HKEY_LOCAL_MACHINE,paths[i],0,KEY_SET_VALUE|KEY_WOW64_64KEY,&key);
    if(s==ERROR_SUCCESS){s=RegDeleteValueW(key,name);RegCloseKey(key);}return {s==ERROR_SUCCESS||missing(static_cast<DWORD>(s)),static_cast<DWORD>(s),0,0};
}
Snapshot readDefault(Registry& registry) {Snapshot s;for(std::size_t i=0;i<5;++i){s.values[i]=registry.read(false,names[i]);s.valid[i]=parseNumber(s.values[i],s.numbers[i]);}return s;}
Mutation writeDefault(Registry& r,const Coordinate& c) {
    const double values[]={c.latitude,c.longitude,c.altitude,c.errorRadius,c.altitudeAccuracy};Mutation m;std::size_t count=0;
    for(std::size_t i=0;i<5;++i){++m.attempted;m.operations[i]=r.write(false,names[i],REG_SZ,asString(values[i]));if(!m.operations[i].success)break;++count;}m.completed=count;
    m.after=readDefault(r);bool matched=count==5;for(std::size_t i=0;i<5;++i)matched=matched && m.after.valid[i] && std::fabs(m.after.numbers[i]-values[i])<0.00000002;
    m.success=matched;m.partial=m.attempted!=0 && !matched;return m;
}
Mutation clearDefault(Registry& r) {Mutation m;std::size_t count=0;for(std::size_t i=0;i<5;++i){++m.attempted;m.operations[i]=r.remove(false,names[i]);if(!m.operations[i].success)break;++count;}m.completed=count;
    m.after=readDefault(r);bool absent=count==5;for(const auto& value:m.after.values)absent=absent && value.known && !value.present;m.success=absent;m.partial=m.attempted!=0 && !absent;return m;}
Operation setProvider(Registry& r,bool disabled) {if(!disabled)return r.remove(true,L"DisableWindowsLocationProvider");DWORD value=1;const auto* p=reinterpret_cast<const std::uint8_t*>(&value);return r.write(true,L"DisableWindowsLocationProvider",REG_DWORD,{p,p+sizeof(value)});}
Service serviceStatus(){Service result;SC_HANDLE manager=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);if(!manager){result.error=GetLastError();return result;}
    SC_HANDLE service=OpenServiceW(manager,L"lfsvc",SERVICE_QUERY_STATUS);if(!service){result.error=GetLastError();CloseServiceHandle(manager);return result;}
    SERVICE_STATUS_PROCESS status{};DWORD needed=0;result.available=QueryServiceStatusEx(service,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&status),sizeof(status),&needed)!=FALSE;
    if(result.available)result.state=status.dwCurrentState;else result.error=GetLastError();CloseServiceHandle(service);CloseServiceHandle(manager);return result;}
Operation resetServiceCache(){SC_HANDLE manager=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);if(!manager)return {false,GetLastError(),0,0};
    SC_HANDLE service=OpenServiceW(manager,L"lfsvc",SERVICE_STOP|SERVICE_QUERY_STATUS);if(!service){DWORD e=GetLastError();CloseServiceHandle(manager);return {false,e,0,0};}
    SERVICE_STATUS status{};const BOOL ok=ControlService(service,SERVICE_CONTROL_STOP,&status);DWORD e=ok?ERROR_SUCCESS:GetLastError();CloseServiceHandle(service);CloseServiceHandle(manager);
    return {ok!=FALSE||e==ERROR_SERVICE_NOT_ACTIVE,e,0,0};}
LiveFix liveFix(DWORD timeoutMs) {
    using namespace ABI::Windows::Foundation;using namespace ABI::Windows::Devices::Geolocation;using Microsoft::WRL::ComPtr;
    LiveFix result;HRESULT hr=RoInitialize(RO_INIT_MULTITHREADED);bool initialized=SUCCEEDED(hr);if(FAILED(hr)&&hr!=RPC_E_CHANGED_MODE){result.hresult=hr;return result;}
    struct Scope{bool active;~Scope(){if(active)RoUninitialize();}} scope{initialized};
    HSTRING id=nullptr;const wchar_t* name=L"Windows.Devices.Geolocation.Geolocator";
    hr=WindowsCreateString(name,static_cast<UINT32>(wcslen(name)),&id);if(FAILED(hr)){result.hresult=hr;return result;}
    ComPtr<IInspectable> object;hr=RoActivateInstance(id,object.GetAddressOf());WindowsDeleteString(id);
    if(SUCCEEDED(hr)&&!object)hr=E_POINTER;ComPtr<IGeolocator> locator;if(SUCCEEDED(hr))hr=object.As(&locator);if(FAILED(hr)||!locator){result.hresult=FAILED(hr)?hr:E_POINTER;return result;}
    locator->put_DesiredAccuracy(PositionAccuracy_High);ComPtr<IAsyncOperation<Geoposition*>> op;hr=locator->GetGeopositionAsync(op.GetAddressOf());
    if(SUCCEEDED(hr)&&!op)hr=E_POINTER;ComPtr<IAsyncInfo> info;if(SUCCEEDED(hr))hr=op.As(&info);if(FAILED(hr)||!info){result.hresult=FAILED(hr)?hr:E_POINTER;return result;}
    const ULONGLONG end=GetTickCount64()+timeoutMs;AsyncStatus state=Started;
    while(SUCCEEDED(hr=info->get_Status(&state)) && state==Started && GetTickCount64()<end)Sleep(50);
    if(state==Started){info->Cancel();result.timedOut=true;result.hresult=HRESULT_FROM_WIN32(WAIT_TIMEOUT);return result;}
    if(FAILED(hr)||state!=Completed){if(SUCCEEDED(hr))info->get_ErrorCode(&hr);result.hresult=hr;return result;}
    ComPtr<IGeoposition> position;hr=op->GetResults(position.GetAddressOf());ComPtr<IGeocoordinate> coordinate;
    if(SUCCEEDED(hr)&&!position)hr=E_POINTER;if(SUCCEEDED(hr))hr=position->get_Coordinate(coordinate.GetAddressOf());ComPtr<IGeocoordinateWithPoint> withPoint;
    if(SUCCEEDED(hr)&&!coordinate)hr=E_POINTER;if(SUCCEEDED(hr))hr=coordinate.As(&withPoint);ComPtr<IGeopoint> point;
    if(SUCCEEDED(hr)&&!withPoint)hr=E_POINTER;if(SUCCEEDED(hr))hr=withPoint->get_Point(point.GetAddressOf());
    BasicGeoposition basic{};if(SUCCEEDED(hr)&&!point)hr=E_POINTER;if(SUCCEEDED(hr))hr=point->get_Position(&basic);if(FAILED(hr)){result.hresult=hr;return result;}
    result.coordinate.latitude=basic.Latitude;result.coordinate.longitude=basic.Longitude;result.coordinate.altitude=basic.Altitude;
    DOUBLE accuracy=0;if(SUCCEEDED(coordinate->get_Accuracy(&accuracy))){result.accuracyKnown=true;result.coordinate.errorRadius=accuracy;}
    ComPtr<IReference<double>> altitude;if(SUCCEEDED(coordinate->get_AltitudeAccuracy(altitude.GetAddressOf()))&&altitude){DOUBLE n=0;if(SUCCEEDED(altitude->get_Value(&n))){result.altitudeAccuracyKnown=true;result.coordinate.altitudeAccuracy=n;}}
    ComPtr<IGeocoordinateWithPositionData> positioned;if(SUCCEEDED(coordinate.As(&positioned))&&positioned){PositionSource source=PositionSource_Unknown;if(SUCCEEDED(positioned->get_PositionSource(&source))){result.sourceKnown=true;result.source=static_cast<std::uint32_t>(source);}}
    result.success=true;result.hresult=S_OK;return result;
}
}
