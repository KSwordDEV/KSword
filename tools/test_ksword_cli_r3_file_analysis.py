"""Verify interrupted reads and typed WinVerifyTrust verdicts with production code."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADER = r'''
#pragma once
#include <Windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
BOOL WINAPI FixtureRead(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
LONG WINAPI FixtureTrust(HWND,GUID*,LPVOID);
BOOL WINAPI FixtureAcquire(HCATADMIN*,const GUID*,PCWSTR,PCCERT_STRONG_SIGN_PARA,DWORD);
BOOL WINAPI FixtureHash(HCATADMIN,HANDLE,DWORD*,BYTE*,DWORD);
HCATINFO WINAPI FixtureEnum(HCATADMIN,BYTE*,DWORD,DWORD,HCATINFO*);
BOOL WINAPI FixtureInfo(HCATINFO,CATALOG_INFO*,DWORD);
BOOL WINAPI FixtureReleaseCatalog(HCATADMIN,HCATINFO,DWORD);
BOOL WINAPI FixtureReleaseAdmin(HCATADMIN,DWORD);
#define ReadFile FixtureRead
#define WinVerifyTrust FixtureTrust
#define CryptCATAdminAcquireContext2 FixtureAcquire
#define CryptCATAdminCalcHashFromFileHandle2 FixtureHash
#define CryptCATAdminEnumCatalogFromHash FixtureEnum
#define CryptCATCatalogInfoFromContext FixtureInfo
#define CryptCATAdminReleaseCatalogContext FixtureReleaseCatalog
#define CryptCATAdminReleaseContext FixtureReleaseAdmin
'''
SOURCE = r'''
#include "mock.h"
#undef ReadFile
#undef WinVerifyTrust
#include "REGISTRY"
#include <fcntl.h>
#include <io.h>
static std::wstring mode;
static unsigned reads,verify,closed;
BOOL WINAPI FixtureAcquire(HCATADMIN* admin,const GUID*,PCWSTR,PCCERT_STRONG_SIGN_PARA,DWORD) {
    if(mode==L"catalog-error") {SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
    *admin=reinterpret_cast<HCATADMIN>(1);return TRUE;
}
BOOL WINAPI FixtureHash(HCATADMIN,HANDLE,DWORD* size,BYTE* bytes,DWORD) {
    if(!bytes){*size=4;return TRUE;} if(*size<4)return FALSE;
    bytes[0]=1;bytes[1]=2;bytes[2]=3;bytes[3]=4;*size=4;return TRUE;
}
HCATINFO WINAPI FixtureEnum(HCATADMIN,BYTE*,DWORD,DWORD,HCATINFO* previous) {
    if((mode==L"catalog-trusted"||mode==L"catalog-bad") && !*previous)return reinterpret_cast<HCATINFO>(2);
    SetLastError(ERROR_NOT_FOUND);return nullptr;
}
BOOL WINAPI FixtureInfo(HCATINFO,CATALOG_INFO* info,DWORD){wcscpy_s(info->wszCatalogFile,L"C:\\fixture.cat");return TRUE;}
BOOL WINAPI FixtureReleaseCatalog(HCATADMIN,HCATINFO,DWORD){return TRUE;}
BOOL WINAPI FixtureReleaseAdmin(HCATADMIN,DWORD){return TRUE;}
BOOL WINAPI FixtureRead(HANDLE file,LPVOID buffer,DWORD size,LPDWORD read,LPOVERLAPPED async) {
    if((mode==L"partial" && ++reads>1) || mode==L"unreadable") {*read=0;SetLastError(ERROR_CRC);return FALSE;}
    return ReadFile(file,buffer,size>4?4:size,read,async);
}
LONG WINAPI FixtureTrust(HWND,GUID*,LPVOID raw) {
    const auto* trust=static_cast<const WINTRUST_DATA*>(raw);
    if(trust->dwStateAction==WTD_STATEACTION_CLOSE){++closed;return ERROR_SUCCESS;}
    ++verify;
    if(trust->dwUIChoice!=WTD_UI_NONE || trust->fdwRevocationChecks!=WTD_REVOKE_NONE || trust->dwProvFlags!=WTD_CACHE_ONLY_URL_RETRIEVAL)return E_INVALIDARG;
    if(trust->dwUnionChoice==WTD_CHOICE_CATALOG) {
        if(!trust->pCatalog || std::wstring(trust->pCatalog->pcwszMemberTag)!=L"01020304" || !trust->pCatalog->hMemberFile)return E_INVALIDARG;
        return mode==L"catalog-trusted" ? ERROR_SUCCESS : TRUST_E_BAD_DIGEST;
    }
    if(mode==L"catalog-trusted"||mode==L"catalog-bad"||mode==L"catalog-error")return TRUST_E_NOSIGNATURE;
    return mode==L"trusted" ? ERROR_SUCCESS : mode==L"no-signature" ? TRUST_E_NOSIGNATURE : mode==L"digest" ? TRUST_E_BAD_DIGEST : mode==L"unsupported" ? TRUST_E_PROVIDER_UNKNOWN : E_INVALIDARG;
}
int wmain(int argc,wchar_t* argv[]) {
    _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
    mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
    ks::cli::registerFileAnalysis();const int rc=ks::cli::dispatchR3(argc,argv).value_or(1);
    if(std::wstring(argv[2])==L"signature" && (verify<1 || closed!=verify))return 9;
    return rc;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-file-analysis-') as temp:
        directory = Path(temp)
        (directory / 'mock.h').write_text(HEADER)
        (directory / 'fixture.cpp').write_text(SOURCE.replace('REGISTRY', (ROOT / 'KswordCLI/CommandRegistry.h').as_posix()))
        data = directory / 'example.bin'
        data.write_bytes(bytes(range(16)))
        sources = ['KswordCLI/CommandRegistry.cpp', 'KswordCLI/R3FileAnalysis.cpp',
                   'shared/usermode/backend/file/FileAnalysis.cpp', 'shared/usermode/backend/file/PathNavigator.cpp']
        binary = directory / 'fixture.exe'
        subprocess.run(['cl', '/nologo', '/std:c++20', '/EHsc', '/utf-8', '/O2', '/DNOMINMAX', '/DUNICODE', '/D_UNICODE',
                        '/FI' + str(directory / 'mock.h'), str(directory / 'fixture.cpp'),
                        *[str(ROOT / source) for source in sources], '/Fe:' + str(binary), '/link', 'Advapi32.lib'], cwd=directory, check=True)
        def run(mode, kind, code):
            result = subprocess.run([str(binary), mode, 'file', kind, 'query', '--path', str(data), '--json'], capture_output=True, timeout=15)
            assert result.returncode == code, (result.returncode, result.stdout, result.stderr)
            return json.loads(result.stdout)['data']
        hashed = run('partial', 'hash', 3)
        assert hashed['digest'] is None and not hashed['complete'] and hashed['bytesRead'] == '4' and hashed['win32Error'] == 23
        entropy = run('partial', 'entropy', 6)
        assert entropy['bitsPerByte'] == 2 and entropy['sampledBytes'] == '4' and entropy['win32Error'] == 23 and not entropy['complete']
        failed = run('unreadable', 'entropy', 3)
        assert failed['bitsPerByte'] is None and failed['sampledBytes'] == '0' and failed['win32Error'] == 23
        assert run('trusted', 'signature', 0)['trusted']
        absent = run('no-signature', 'signature', 6)
        assert absent['trusted'] is None and absent['signatureState'] == 'no-embedded-signature' and absent['embedded']['state'] == 'no-embedded-signature' and absent['catalogChecked']
        bad = run('digest', 'signature', 0)
        assert not bad['trusted'] and bad['embedded']['state'] == 'bad-digest' and bad['trustStatus'] == '0x80096010'
        assert run('unsupported', 'signature', 5)['trustStatus'] == '0x800b0001'
        assert run('error', 'signature', 3)['trustStatus'] == '0x80070057'
        catalog = run('catalog-trusted', 'signature', 0)
        assert catalog['trusted'] and catalog['catalog']['trusted'] and catalog['catalog']['hashAlgorithm'] == 'SHA256' and catalog['embedded']['trusted'] is None
        rejected = run('catalog-bad', 'signature', 0)
        assert not rejected['trusted'] and not rejected['catalog']['trusted'] and rejected['catalog']['searchComplete'] and rejected['catalog']['catalogsExamined'] == 2
        unavailable = run('catalog-error', 'signature', 6)
        assert unavailable['trusted'] is None and not unavailable['catalogChecked'] and unavailable['catalog']['win32Error'] == 5
        print('R3_ANALYSIS_FIXTURE_PASS failed read cannot yield digest, partial entropy, trust status and close')


if __name__ == '__main__':
    main()
