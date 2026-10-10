"""PhysicalDisk per-field availability, scope, empty results, budgets and cleanup."""
from pathlib import Path
import json
import subprocess
import tempfile
from test_ksword_cli_r3_hardware_performance import SOURCE
ROOT=Path(__file__).resolve().parents[1]

def main():
    with tempfile.TemporaryDirectory(prefix='ksword-r3-disk-') as temp:
        directory=Path(temp)
        source=SOURCE.replace('registerHardwarePerformance','registerHardwareDisk')
        source=source.replace('L"Bytes Sent"','L"Disk Write Bytes"').replace('L"network-fail"','L"disk-field-fail"')
        source=source.replace('items[0].FmtValue.doubleValue=19','items[0].FmtValue.doubleValue=paths[counter].find(L"% Disk Time")!=std::wstring::npos?250:19')
        for key,path in {'HEADER':'shared/usermode/backend/hardware/PerformanceSampler.h','REGISTRY':'KswordCLI/CommandRegistry.h','CPP':'shared/usermode/backend/hardware/SystemPerformanceSampler.cpp'}.items():source=source.replace(key,(ROOT/path).as_posix())
        (directory/'fixture.cpp').write_text(source,encoding='utf-8');binary=directory/'fixture.exe'
        subprocess.run(['cl','/nologo','/std:c++20','/EHsc','/utf-8','/O2','/DNOMINMAX','/DUNICODE','/D_UNICODE',str(directory/'fixture.cpp'),
                        *[str(ROOT/path) for path in ['KswordCLI/CommandRegistry.cpp','KswordCLI/R3Cancellation.cpp','KswordCLI/R3HardwareDisk.cpp','shared/usermode/backend/hardware/DiskActivitySampler.cpp','shared/usermode/backend/hardware/HardwareStatsFormatting.cpp']],
                        '/Fe:'+str(binary),'/link','Advapi32.lib','Pdh.lib','User32.lib'],cwd=directory,check=True)
        def run(mode,code,extra=()):
            result=subprocess.run([str(binary),mode,'hardware','disk','sample','--json',*extra],capture_output=True,timeout=15)
            assert result.returncode==code,(mode,result.returncode,result.stdout,result.stderr)
            return json.loads(result.stdout)['data']
        valid=run('valid',0)['samples'][0];assert len(valid['sources'])==9 and all(r'\PhysicalDisk' in s['path'] for s in valid['sources'])
        disk=valid['disks'][0];assert disk['busyPercent']==250 and disk['readLatencySeconds']==19
        missing=run('disk-field-fail',6)['samples'][0]['disks'][0];assert missing['writeBytesPerSecond'] is None and missing['readBytesPerSecond']==19
        assert run('array-empty',0)['samples'][0]['enumeratedCount']=='0'
        assert run('valid',0,['--instance','nonexistent'])['samples'][0]['matchedCount']=='0'
        assert run('bad-count',4)['samples'][0]['sources'][0]['evidence']['malformed']
        assert run('bad-pointer',4)['samples'][0]['sources'][0]['evidence']['malformed']
        assert run('open-denied',5)['samples'][0]['queryStatus']=='0xc0000bdb'
        assert run('collect-fail',5)['samples'][0]['collectStatus']=='0xc0000bc6'
        assert run('baseline-fail',6)['samples'][0]['baselineStatus']=='0xc0000bc6'
        assert not run('close-fail',6)['queryClosed']
        startup=subprocess.STARTUPINFO();startup.dwFlags=subprocess.STARTF_USESHOWWINDOW;startup.wShowWindow=subprocess.SW_HIDE
        result=subprocess.run([str(binary),'cancel','hardware','disk','sample','--samples','30','--interval-ms','250','--json'],capture_output=True,timeout=15,creationflags=subprocess.CREATE_NEW_CONSOLE,startupinfo=startup)
        assert result.returncode==6,(result.returncode,result.stdout,result.stderr)
        cancel=json.loads(result.stdout)['data'];assert cancel['cancelled'] and cancel['queryClosed'] and cancel['returnedSamples']<30
        print('R3_DISK_FIXTURE_PASS per-field unknowns, nine-counter scope, uncapped busy, raw seconds, native errors, empty/filter misses, cancellation/ownership')

if __name__=='__main__':main()
