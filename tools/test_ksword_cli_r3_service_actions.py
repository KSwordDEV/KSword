"""Exercise CLI service mutations through a fake SCM; never changes real services."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = r'''
#include "REGISTRY"
#include "ACTIONS"
#include "ENUMERATOR"
#include "SERVICE"
#include <fcntl.h>
#include <io.h>
static std::wstring mode;
static ks::service::ServiceRecord record;
static ks::service::FailureSettings recovery;
namespace ks::service {
bool QueryServiceRecord(const std::wstring&,ServiceRecord* out,std::string*,std::uint32_t* err){if(mode==L"read-fail"){*err=ERROR_ACCESS_DENIED;return false;}*out=record;*err=0;return true;}
bool ChangeServiceConfiguration(const std::wstring&,const ServiceConfigUpdate& u,std::string*,std::uint32_t* e){
    if(mode==L"primary-fail"){*e=ERROR_ACCESS_DENIED;return false;}*e=0;
    if(u.changeServiceType)record.config.serviceType=u.serviceType;if(u.changeStartType)record.config.startType=u.startType;
    if(u.changeErrorControl)record.config.errorControl=u.errorControl;if(u.changeBinaryPath)record.config.binaryPath=u.binaryPath;
    if(u.changeLoadOrderGroup)record.config.loadOrderGroup=u.loadOrderGroup;
    if(u.changeDependencies)record.config.dependenciesMultiSz=u.dependenciesMultiSz.size()==2?std::wstring{}:u.dependenciesMultiSz;
    if(u.changeAccount)record.config.accountName=u.accountName;if(u.changeDisplayName)record.config.displayName=u.displayName;return true;
}
bool SetServiceDescription(const std::wstring&,const std::wstring& text,std::string*,std::uint32_t* e){if(mode==L"description-fail"){*e=ERROR_ACCESS_DENIED;return false;}record.description=text;*e=0;return true;}
bool SetDelayedAutoStart(const std::wstring&,bool x,std::string*,std::uint32_t* e){record.config.delayedAutoStart=x;*e=0;return true;}
bool QueryServiceFailureSettings(const std::wstring&,FailureSettings* out,std::string*,std::uint32_t* e){*out=recovery;*e=0;if(mode==L"recovery-unknown")out->hasFailureActions=false;return true;}
bool ApplyServiceFailureSettings(const std::wstring&,const FailureSettings& value,std::string*,std::uint32_t* e){recovery=value;if(mode==L"recovery-fail"){*e=ERROR_ACCESS_DENIED;return false;}*e=0;return true;}
bool DeleteServiceByName(const std::wstring&,bool,std::uint32_t,std::string*,std::uint32_t* e){if(mode==L"delete-fail"){*e=ERROR_ACCESS_DENIED;return false;}*e=0;return true;}
bool StopServiceByName(const std::wstring&,std::uint32_t,std::uint32_t,ServiceStatus* s,std::string*,std::uint32_t* e){s->currentState=SERVICE_STOPPED;*e=0;return true;}
bool EnumerateServiceRecords(std::uint32_t,std::uint32_t,std::vector<ServiceRecord>* out,std::string*,std::uint32_t* e){out->clear();*e=0;return true;}
}
namespace ks::r3::service {
ServiceEnumerationResult EnumerateServices(){return {};}
ServiceEnumerationResult QuerySingleService(const std::wstring&){return {};}
ServiceDetailSnapshot QueryServiceReadOnlyDetails(const ServiceEntry&){return {};}
std::wstring ServiceDetailAvailabilityText(ServiceDetailAvailability){return L"unknown";}
std::wstring ResolveServiceImagePathForBrowser(const std::wstring& s){return s;}
ServiceActionResult StartServiceEntry(const std::wstring&){return {};}
ServiceActionResult StopServiceEntry(const std::wstring&){return {};}
ServiceActionResult PauseServiceEntry(const std::wstring&){return {};}
ServiceActionResult ContinueServiceEntry(const std::wstring&){return {};}
ServiceActionResult ApplyServiceStartType(const std::wstring&,ServiceStartTypeChoice){return {};}
}
int wmain(int argc,wchar_t* argv[]){
    _setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
    mode=argv[1];for(int i=1;i+1<argc;++i)argv[i]=argv[i+1];--argc;
    record.hasStatus=record.hasConfig=record.hasDescription=true;record.status.currentState=SERVICE_STOPPED;
    record.config.hasDelayedAutoStart=true;record.config.startType=SERVICE_DEMAND_START;record.config.binaryPath=L"C:\\test.exe";
    recovery.hasFailureActions=recovery.hasFailureActionsFlag=true;recovery.command=L"old";
    ks::cli::registerService();return ks::cli::dispatchR3(argc,argv).value_or(1);
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix="ksword-service-cli-") as temp:
        temp = Path(temp)
        source = SOURCE
        for marker, path in {"REGISTRY":"KswordCLI/CommandRegistry.h", "ACTIONS":"shared/usermode/backend/service/ServiceActions.h", "ENUMERATOR":"shared/usermode/backend/service/ServiceEnumerator.h", "SERVICE":"Ksword5.1/Ksword5.1/ksword/service/service.h"}.items():
            source = source.replace('"'+marker+'"', '"'+(ROOT/path).as_posix()+'"')
        (temp/'fixture.cpp').write_text(source, encoding='utf-8')
        exe=temp/'fixture.exe'
        paths=['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Service.cpp','KswordCLI/R3Input.cpp']
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE',str(temp/'fixture.cpp'),*[str(ROOT/p) for p in paths],'/Fe:'+str(exe),'/link','Advapi32.lib'],cwd=temp,check=True)
        def run(mode,*args):
            result=subprocess.run([str(exe),mode,*args,'--json'],capture_output=True,timeout=20)
            return result.returncode,json.loads(result.stdout),result.stderr.decode(errors='replace')
        code,result,err=run('ok','service','config','set','--name','Fixture','--display-name','Updated','--description','text','--dependencies','A;+B','--delayed-auto','1','--confirm')
        assert code==0 and result['data']['verified'] and result['data']['descriptionSucceeded'],(code,result,err)
        code,result,err=run('ok','service','config','set','--name','Fixture','--clear-description','1','--clear-dependencies','1','--confirm')
        assert code==0 and result['data']['verified'],(code,result,err)
        secret=temp/'password.txt';secret.write_text('fixture-secret',encoding='utf-8')
        code,result,err=run('ok','service','config','set','--name','Fixture','--account','LocalSystem','--password-file',str(secret),'--confirm')
        assert code==6 and result['data']['passwordWritten'] and result['data']['passwordVerified'] is None and 'fixture-secret' not in json.dumps(result),(code,result,err)
        code,result,err=run('description-fail','service','config','set','--name','Fixture','--display-name','Updated','--description','text','--confirm')
        assert code==6 and result['data']['primarySucceeded'] and not result['data']['descriptionSucceeded'],(code,result,err)
        code,result,err=run('primary-fail','service','config','set','--name','Fixture','--display-name','Updated','--confirm')
        assert code==3 and result['data']['win32Error']==5,(code,result,err)
        code,result,err=run('ok','service','recovery','set','--name','Fixture','--reset-seconds','60','--actions','restart:1000,none:0','--command','new','--non-crash','1','--confirm')
        assert code==0 and result['data']['verified'],(code,result,err)
        code,result,err=run('ok','service','recovery','set','--name','Fixture','--clear-actions','1','--clear-command','1','--confirm')
        assert code==0 and result['data']['verified'],(code,result,err)
        code,result,err=run('recovery-unknown','service','recovery','set','--name','Fixture','--actions','none:0','--confirm')
        assert code==5,(code,result,err)
        code,result,err=run('recovery-fail','service','recovery','set','--name','Fixture','--actions','none:0','--confirm')
        assert code==6 and not result['data']['requestSucceeded'],(code,result,err)
        code,result,err=run('ok','service','delete','--name','Fixture','--confirm')
        assert code==0 and result['data']['registrationDeleteAccepted'],(code,result,err)
        code,result,err=run('delete-fail','service','delete','--name','Fixture','--confirm')
        assert code==3 and not result['data']['registrationDeleteAccepted'],(code,result,err)
        code,result,err=run('ok','service','delete','--name','Fixture','--delete-file','1','--confirm')
        assert code==1,(code,result,err)
        code,result,err=run('ok','service','delete','--name','Fixture')
        assert code==1,(code,result,err)
        print('R3_SERVICE_ACTIONS_FIXTURE_PASS config, partial writes, recovery, deletion and confirmation')

if __name__=='__main__':
    main()
