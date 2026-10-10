"""Run a real CLI R3 feature suite in the existing VMware clone, without a driver.

All runtime reports, uploaded runners and artifacts live outside the repository.
The caller owns VM power/snapshot isolation; this runner never changes the driver.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
from ksword_cli_vm import Guest

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--vmx', required=True)
    parser.add_argument('--dll', required=True)
    parser.add_argument('--feature', required=True)
    parser.add_argument('--report-dir', type=Path, required=True)
    args = parser.parse_args()
    if not args.feature.replace('-', '').isalnum():
        parser.error('invalid feature name')
    reports = args.report_dir.resolve()
    if reports == ROOT or ROOT in reports.parents:
        parser.error('runtime reports must be outside the repository')
    reports.mkdir(parents=True, exist_ok=True)
    cli = ROOT / 'Ksword5.1/x64/Release/KswordCLI.exe'
    guest_root = r'C:\KSwordCliLab'
    local_runner = reports / (args.feature + '-runner.ps1')
    feature = args.feature
    local_runner.write_text(f'''$ErrorActionPreference='Stop'
Start-Transcript '{guest_root}\\{feature}.log' -Force
$rc=0
try {{
    $service=Get-Service KswordARK -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {{ throw 'Driver must remain stopped for the R3 suite' }}
    & '{guest_root}\\Test-KSwordCliR3.ps1' -Cli '{guest_root}\\KswordCLI-R3.exe' -Feature '{feature}' -InGuest -ReportPath '{guest_root}\\{feature}.json'
}} catch {{ Write-Output $_; $rc=1 }} finally {{ Stop-Transcript }}
exit $rc
''', encoding='utf-8-sig')
    guest = Guest(args.dll, args.vmx, 'Administrator', '')
    try:
        guest.copy(str(cli), guest_root + r'\KswordCLI-R3.exe')
        for name in ('MSVCP140.dll', 'VCRUNTIME140.dll', 'VCRUNTIME140_1.dll'):
            guest.copy(str(cli.parent / name), guest_root + '\\' + name)
        if feature in ('service', 'startup-actions', 'process-threads', 'process-modules', 'process-hotkeys', 'window', 'window-hierarchy', 'monitor-etw'):
            guest.copy(str(Path(os.environ['LOCALAPPDATA']) / 'KSwordTestBuilds/CLI-R3/R3Fixture.exe'), guest_root + r'\R3Fixture.exe')
        if feature == 'process-modules':
            guest.copy(str(Path(os.environ['LOCALAPPDATA']) / 'KSwordTestBuilds/CLI-R3/R3ModuleFixture.dll'), guest_root + r'\R3ModuleFixture.dll')
        if feature == 'window-capture':
            guest.copy(str(Path(os.environ['LOCALAPPDATA']) / 'KSwordTestBuilds/CLI-R3/R3CaptureRunner.exe'), guest_root + r'\R3CaptureRunner.exe')
        for name in ('Test-KSwordCliR3.ps1', 'KswordCliR3TestSupport.ps1'):
            guest.copy(str(ROOT / 'tools' / name), guest_root + '\\' + name)
        if feature == 'privilege':
            guest.copy(str(ROOT / 'tools/Test-KSwordCliR3Privilege.ps1'), guest_root + r'\Test-KSwordCliR3Privilege.ps1')
        if feature in ('kernel-namespace', 'kernel-directory'):
            guest.copy(str(ROOT / 'tools/KswordCliR3NamespaceOracle.ps1'), guest_root + r'\KswordCliR3NamespaceOracle.ps1')
        extra_suite = ROOT / ('tools/Test-KSwordCliR3-' + feature + '.ps1')
        if extra_suite.is_file():
            guest.copy(str(extra_suite), guest_root + '\\' + extra_suite.name)
        guest.copy(str(local_runner), guest_root + r'\r3-feature-runner.ps1')
        rc = guest.run(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                       r'-NoProfile -ExecutionPolicy Bypass -File C:\KSwordCliLab\r3-feature-runner.ps1',
                       180 if feature == 'process-controls' else 60)
        guest.copy(guest_root + '\\' + feature + '.log', str(reports / (feature + '.log')), False)
        if rc:
            raise RuntimeError(f'Guest suite failed: {reports / (feature + ".log")}')
        guest.copy(guest_root + '\\' + feature + '.json', str(reports / (feature + '.json')), False)
        result = json.loads((reports / (feature + '.json')).read_text(encoding='utf-8-sig'))
        assert result['success'] and result['driver'] in ('Stopped', 'Absent')
        assert result['sha256'].lower() == hashlib.sha256(cli.read_bytes()).hexdigest()
        assert {item['name'] for item in result['runtime']} == {'MSVCP140.dll', 'VCRUNTIME140.dll', 'VCRUNTIME140_1.dll'}
        for dependency in result['runtime']:
            assert dependency['sha256'].lower() == hashlib.sha256((cli.parent / dependency['name']).read_bytes()).hexdigest()
        print(f'VM_PASS feature={feature} cases={len(result["cases"])} driver={result["driver"]}')
    finally:
        guest.close()


if __name__ == '__main__':
    main()
