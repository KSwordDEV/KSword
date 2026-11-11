#pragma once
#include "runtime_probe_support.h"
#include <objbase.h>
#include <bcrypt.h>
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"advapi32.lib")
namespace apimon_probe {
class ProbeFactory final : public IClassFactory {
    LONG refs_=1;
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void** out) override {
        if(!out)return E_POINTER; *out=nullptr;
        if(iid==IID_IUnknown || iid==IID_IClassFactory){*out=static_cast<IClassFactory*>(this);AddRef();return S_OK;}return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override {return static_cast<ULONG>(InterlockedIncrement(&refs_));}
    ULONG STDMETHODCALLTYPE Release() override {LONG n=InterlockedDecrement(&refs_);if(!n)delete this;return static_cast<ULONG>(n);}
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown*,REFIID,void**) override {return CLASS_E_CLASSNOTAVAILABLE;}
    HRESULT STDMETHODCALLTYPE LockServer(BOOL) override {return S_OK;}
};
inline void RunServiceSecurityCases() {
#define C(ID, MOD, API, ...) Call<decltype(&::API)>(ID,L##MOD,#API,__VA_ARGS__)
#define C0(ID, MOD, API) Call<decltype(&::API)>(ID,L##MOD,#API)
    const HRESULT init=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    GUID generated{}; C(760,"Ole32.dll",CoCreateGuid,&generated);
    const GUID guid={0x9ba413a5,0x133f,0x4a13,{0x9a,0x82,0x30,0x46,0x18,0xf0,0x6a,0x48}};
    DWORD tid=0; C(761,"Ole32.dll",CoGetCallerTID,&tid);
    GUID logical{}; C(762,"Ole32.dll",CoGetCurrentLogicalThreadId,&logical);
    ULONG_PTR token=0; C(763,"Ole32.dll",CoGetContextToken,&token);
    auto factory=new ProbeFactory;
    DWORD cookie=0;
    // A fresh class identity and in-process registration belong only to this process.
    C(772,"Ole32.dll",CoRegisterClassObject,guid,static_cast<IUnknown*>(factory),DWORD(CLSCTX_LOCAL_SERVER),DWORD(REGCLS_MULTIPLEUSE|REGCLS_SUSPENDED),&cookie);
    C0(765,"Ole32.dll",CoResumeClassObjects);
    C0(766,"Ole32.dll",CoSuspendClassObjects);
    C(764,"Ole32.dll",CoRevokeClassObject,cookie);
    C0(765,"Ole32.dll",CoResumeClassObjects);
    C(767,"Ole32.dll",CoDisconnectObject,static_cast<IUnknown*>(factory),DWORD(0));
    C(768,"Ole32.dll",CoLockObjectExternal,static_cast<IUnknown*>(factory),TRUE,TRUE);
    C(768,"Ole32.dll",CoLockObjectExternal,static_cast<IUnknown*>(factory),FALSE,TRUE);
    CLSID proxy{}; C(769,"Ole32.dll",CoGetPSClsid,IID_IUnknown,&proxy);
    C(770,"Ole32.dll",CoRegisterPSClsid,guid,CLSID_NULL);
    void* context=nullptr; C(771,"Ole32.dll",CoGetCallContext,IID_IUnknown,&context); if(context)static_cast<IUnknown*>(context)->Release();
    IStream* stream=nullptr; C(860,"Ole32.dll",CreateStreamOnHGlobal,static_cast<HGLOBAL>(nullptr),TRUE,&stream);
    if(stream) {
        C(773,"Ole32.dll",CoMarshalHresult,stream,E_FAIL);
        LARGE_INTEGER zero{}; stream->Seek(zero,STREAM_SEEK_SET,nullptr);
        HRESULT result{}; C(774,"Ole32.dll",CoUnmarshalHresult,stream,&result);
        stream->Seek(zero,STREAM_SEEK_SET,nullptr);
        C(775,"Ole32.dll",CoReleaseMarshalData,stream);
        stream->Seek(zero,STREAM_SEEK_SET,nullptr); void* unpacked=nullptr;
        C(776,"Ole32.dll",CoUnmarshalInterface,stream,IID_IUnknown,&unpacked); if(unpacked)static_cast<IUnknown*>(unpacked)->Release();
        stream->Seek(zero,STREAM_SEEK_SET,nullptr);
        HRESULT marshaled=C(777,"Ole32.dll",CoMarshalInterface,stream,IID_IUnknown,static_cast<IUnknown*>(factory),DWORD(MSHCTX_INPROC),static_cast<LPVOID>(nullptr),DWORD(MSHLFLAGS_NORMAL));
        if(SUCCEEDED(marshaled)){stream->Seek(zero,STREAM_SEEK_SET,nullptr);C(775,"Ole32.dll",CoReleaseMarshalData,stream);}
        ULONG bytes=0; C(778,"Ole32.dll",CoGetMarshalSizeMax,&bytes,IID_IUnknown,static_cast<IUnknown*>(factory),DWORD(MSHCTX_INPROC),static_cast<LPVOID>(nullptr),DWORD(MSHLFLAGS_NORMAL));
        stream->Release();
    } else for(unsigned id=773;id<=778;++id)Skip(id,"memory_stream_creation_failed");
    IStream* ownStream=nullptr;
    C(860,"Ole32.dll",CreateStreamOnHGlobal,static_cast<HGLOBAL>(nullptr),TRUE,&ownStream);
    HGLOBAL global=nullptr;
    if(ownStream){C(861,"Ole32.dll",GetHGlobalFromStream,ownStream,&global);ownStream->Release();}
    else Skip(861,"memory_stream_creation_failed");
    IMalloc* allocator=nullptr; C(862,"Ole32.dll",CoGetMalloc,DWORD(1),&allocator); if(allocator)allocator->Release();
    APTTYPE apt{}; APTTYPEQUALIFIER qualifier{}; C(863,"Ole32.dll",CoGetApartmentType,&apt,&qualifier);
    CLSID parsed{}; C(864,"Ole32.dll",CLSIDFromString,L"{00000000-0000-0000-C000-000000000046}",&parsed);
    LPOLESTR text=nullptr; C(865,"Ole32.dll",StringFromCLSID,IID_IUnknown,&text); CoTaskMemFree(text); text=nullptr;
    IID iid{}; C(866,"Ole32.dll",IIDFromString,L"{00000000-0000-0000-C000-000000000046}",&iid);
    C(867,"Ole32.dll",StringFromIID,IID_IUnknown,&text); CoTaskMemFree(text); text=nullptr;
    C(868,"Ole32.dll",ProgIDFromCLSID,CLSID_NULL,&text); CoTaskMemFree(text);
    context=nullptr; C(869,"Ole32.dll",CoGetObjectContext,IID_IUnknown,&context); if(context)static_cast<IUnknown*>(context)->Release();
    IBindCtx* bind=nullptr; C(870,"Ole32.dll",CreateBindCtx,DWORD(0),&bind); if(bind)bind->Release();
    IRunningObjectTable* rot=nullptr; C(871,"Ole32.dll",GetRunningObjectTable,DWORD(0),&rot); if(rot)rot->Release();
    factory->Release(); if(SUCCEEDED(init))CoUninitialize();

    BCRYPT_ALG_HANDLE aes=nullptr,sha=nullptr,rsa=nullptr,ecdh=nullptr;
    BCryptOpenAlgorithmProvider(&aes,BCRYPT_AES_ALGORITHM,nullptr,0);
    BCryptOpenAlgorithmProvider(&sha,BCRYPT_SHA256_ALGORITHM,nullptr,0);
    BCryptOpenAlgorithmProvider(&rsa,BCRYPT_RSA_ALGORITHM,nullptr,0);
    BCryptOpenAlgorithmProvider(&ecdh,BCRYPT_ECDH_P256_ALGORITHM,nullptr,0);
    ULONG prop=0,needed=0;
    C(779,"Bcrypt.dll",BCryptGetProperty,aes,BCRYPT_BLOCK_LENGTH,reinterpret_cast<PUCHAR>(&prop),ULONG(sizeof(prop)),&needed,ULONG(0));
    wchar_t chaining[]=BCRYPT_CHAIN_MODE_CBC;
    C(780,"Bcrypt.dll",BCryptSetProperty,aes,BCRYPT_CHAINING_MODE,reinterpret_cast<PUCHAR>(chaining),ULONG(sizeof(chaining)),ULONG(0));
    BCRYPT_KEY_HANDLE rsaKey=nullptr;
    C(781,"Bcrypt.dll",BCryptGenerateKeyPair,rsa,&rsaKey,ULONG(1024),ULONG(0));
    C(782,"Bcrypt.dll",BCryptFinalizeKeyPair,rsaKey,ULONG(0));
    BCRYPT_HASH_HANDLE hash=nullptr,hashCopy=nullptr; BCryptCreateHash(sha,&hash,nullptr,0,nullptr,0,0);
    C(783,"Bcrypt.dll",BCryptDuplicateHash,hash,&hashCopy,static_cast<PUCHAR>(nullptr),ULONG(0),ULONG(0));
    UCHAR testKey[16]{}; BCRYPT_KEY_HANDLE symmetric=nullptr,keyCopy=nullptr;
    BCryptGenerateSymmetricKey(aes,&symmetric,nullptr,0,testKey,sizeof(testKey),0);
    C(784,"Bcrypt.dll",BCryptDuplicateKey,symmetric,&keyCopy,static_cast<PUCHAR>(nullptr),ULONG(0),ULONG(0));
    C(785,"Bcrypt.dll",BCryptExportKey,rsaKey,static_cast<BCRYPT_KEY_HANDLE>(nullptr),BCRYPT_RSAPUBLIC_BLOB,static_cast<PUCHAR>(nullptr),ULONG(0),&needed,ULONG(0));
    UCHAR digest[32]{},signature[256]{}; BCRYPT_PKCS1_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM};
    C(786,"Bcrypt.dll",BCryptSignHash,rsaKey,&padding,digest,ULONG(sizeof(digest)),signature,ULONG(sizeof(signature)),&needed,ULONG(BCRYPT_PAD_PKCS1));
    C(787,"Bcrypt.dll",BCryptVerifySignature,rsaKey,&padding,digest,ULONG(sizeof(digest)),signature,needed,ULONG(BCRYPT_PAD_PKCS1));
    BCRYPT_KEY_HANDLE a=nullptr,b=nullptr;
    C(781,"Bcrypt.dll",BCryptGenerateKeyPair,ecdh,&a,ULONG(256),ULONG(0)); C(782,"Bcrypt.dll",BCryptFinalizeKeyPair,a,ULONG(0));
    C(781,"Bcrypt.dll",BCryptGenerateKeyPair,ecdh,&b,ULONG(256),ULONG(0)); C(782,"Bcrypt.dll",BCryptFinalizeKeyPair,b,ULONG(0));
    BCRYPT_SECRET_HANDLE secret=nullptr; C(788,"Bcrypt.dll",BCryptSecretAgreement,a,b,&secret,ULONG(0));
    C(789,"Bcrypt.dll",BCryptDestroySecret,secret);
    if(a)BCryptDestroyKey(a); if(b)BCryptDestroyKey(b); if(rsaKey)BCryptDestroyKey(rsaKey); if(symmetric)BCryptDestroyKey(symmetric); if(keyCopy)BCryptDestroyKey(keyCopy);
    if(hash)BCryptDestroyHash(hash); if(hashCopy)BCryptDestroyHash(hashCopy);
    if(aes)BCryptCloseAlgorithmProvider(aes,0); if(sha)BCryptCloseAlgorithmProvider(sha,0); if(rsa)BCryptCloseAlgorithmProvider(rsa,0); if(ecdh)BCryptCloseAlgorithmProvider(ecdh,0);

    SID_IDENTIFIER_AUTHORITY authority=SECURITY_NT_AUTHORITY; BYTE source[SECURITY_MAX_SID_SIZE]{},destination[SECURITY_MAX_SID_SIZE]{};
    C(791,"Advapi32.dll",InitializeSid,static_cast<PSID>(source),&authority,BYTE(1));
    C(790,"Advapi32.dll",CopySid,DWORD(sizeof(destination)),static_cast<PSID>(destination),static_cast<PSID>(source));
    SECURITY_DESCRIPTOR sd{}; C(794,"Advapi32.dll",InitializeSecurityDescriptor,&sd,DWORD(SECURITY_DESCRIPTOR_REVISION));
    PSID owner=nullptr,group=nullptr; BOOL defaulted=FALSE,present=FALSE; PACL acl=nullptr;
    C(792,"Advapi32.dll",GetSecurityDescriptorOwner,&sd,&owner,&defaulted);
    C(793,"Advapi32.dll",GetSecurityDescriptorGroup,&sd,&group,&defaulted);
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD rev=0; C(795,"Advapi32.dll",GetSecurityDescriptorControl,&sd,&control,&rev);
    C(796,"Advapi32.dll",GetSecurityDescriptorDacl,&sd,&present,&acl,&defaulted);
    C(797,"Advapi32.dll",GetSecurityDescriptorSacl,&sd,&present,&acl,&defaulted);
    C(872,"Advapi32.dll",SetSecurityDescriptorOwner,&sd,static_cast<PSID>(source),FALSE);
    C(873,"Advapi32.dll",SetSecurityDescriptorGroup,&sd,static_cast<PSID>(source),FALSE);
    C(874,"Advapi32.dll",SetSecurityDescriptorDacl,&sd,TRUE,static_cast<PACL>(nullptr),FALSE);
    C(875,"Advapi32.dll",SetSecurityDescriptorSacl,&sd,FALSE,static_cast<PACL>(nullptr),FALSE);
    C(876,"Advapi32.dll",SetSecurityDescriptorControl,&sd,SECURITY_DESCRIPTOR_CONTROL(SE_DACL_PROTECTED),SECURITY_DESCRIPTOR_CONTROL(SE_DACL_PROTECTED));
    BYTE relative[512]{}; DWORD relativeSize=sizeof(relative); C(877,"Advapi32.dll",MakeSelfRelativeSD,&sd,static_cast<PSECURITY_DESCRIPTOR>(relative),&relativeSize);
    SECURITY_DESCRIPTOR absolute{}; DWORD absSize=sizeof(absolute),daclSize=0,saclSize=0,ownerSize=sizeof(source),groupSize=sizeof(destination); BYTE ownerBuffer[SECURITY_MAX_SID_SIZE]{},groupBuffer[SECURITY_MAX_SID_SIZE]{};
    C(878,"Advapi32.dll",MakeAbsoluteSD,static_cast<PSECURITY_DESCRIPTOR>(relative),&absolute,&absSize,static_cast<PACL>(nullptr),&daclSize,static_cast<PACL>(nullptr),&saclSize,static_cast<PSID>(ownerBuffer),&ownerSize,static_cast<PSID>(groupBuffer),&groupSize);
    UCHAR rm=0; C(879,"Advapi32.dll",GetSecurityDescriptorRMControl,&sd,&rm);
    // A real SCM handle with the wrong object type exercises failure without touching services.
    SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);
    if(scm) {
        SERVICE_STATUS status{}; DWORD bytes=0; BYTE buffer[64]{};
        C(798,"Advapi32.dll",QueryServiceStatus,scm,&status);
        C(799,"Advapi32.dll",QueryServiceConfig2W,scm,DWORD(SERVICE_CONFIG_DESCRIPTION),buffer,DWORD(sizeof(buffer)),&bytes);
        C(800,"Advapi32.dll",QueryServiceConfig2A,scm,DWORD(SERVICE_CONFIG_DESCRIPTION),buffer,DWORD(sizeof(buffer)),&bytes);
        // Existing service, opened only for status/configuration reads. Both success
        // and environment-dependent access failures are recorded as actual calls.
        SC_HANDLE service=OpenServiceW(scm,L"RpcSs",SERVICE_QUERY_STATUS|SERVICE_QUERY_CONFIG);
        if(service) {
            BYTE description[4096]{};
            C(798,"Advapi32.dll",QueryServiceStatus,service,&status);
            bytes=0; C(799,"Advapi32.dll",QueryServiceConfig2W,service,DWORD(SERVICE_CONFIG_DESCRIPTION),description,DWORD(sizeof(description)),&bytes);
            bytes=0; C(800,"Advapi32.dll",QueryServiceConfig2A,service,DWORD(SERVICE_CONFIG_DELAYED_AUTO_START_INFO),description,DWORD(sizeof(description)),&bytes);
            CloseServiceHandle(service);
        } else for(unsigned id=798;id<=800;++id)Skip(id,"open_rpcss_query_failed");
        CloseServiceHandle(scm);
    } else for(unsigned id=798;id<=800;++id)Skip(id,"open_scm_failed");
#undef C
#undef C0
}
}
