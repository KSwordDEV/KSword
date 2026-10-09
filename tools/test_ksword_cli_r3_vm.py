"""Run a real CLI R3 feature suite in the existing VMware clone, without a driver.

All runtime reports, uploaded runners and artifacts live outside the repository.
The caller owns VM power/snapshot isolation; this runner never changes the driver.
"""
import argparse
import hashlib
import json
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
        for name in ('Test-KSwordCliR3.ps1', 'KswordCliR3TestSupport.ps1'):
            guest.copy(str(ROOT / 'tools' / name), guest_root + '\\' + name)
        guest.copy(str(local_runner), guest_root + r'\r3-feature-runner.ps1')
        rc = guest.run(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                       r'-NoProfile -ExecutionPolicy Bypass -File C:\KSwordCliLab\r3-feature-runner.ps1', 60)
        guest.copy(guest_root + '\\' + feature + '.log', str(reports / (feature + '.log')), False)
        if rc:
            raise RuntimeError(f'Guest suite failed: {reports / (feature + ".log")}')
        guest.copy(guest_root + '\\' + feature + '.json', str(reports / (feature + '.json')), False)
        result = json.loads((reports / (feature + '.json')).read_text(encoding='utf-8-sig'))
        assert result['success'] and result['driver'] in ('Stopped', 'Absent')
        assert result['sha256'].lower() == hashlib.sha256(cli.read_bytes()).hexdigest()
        print(f'VM_PASS feature={feature} cases={len(result["cases"])} driver={result["driver"]}')
    finally:
        guest.close()


if __name__ == '__main__':
    main()
