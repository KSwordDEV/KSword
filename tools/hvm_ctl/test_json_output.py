"""Use the production query formatter and Windows PowerShell 5.1 pipe decoder."""
import json
import pathlib
import re
import subprocess

HERE = pathlib.Path(__file__).resolve().parent
root = HERE.parents[1]
fixture = root / 'tools/hvm_ctl/test_query_json.exe'
cli = root / 'tools/hvm_ctl/hvm_ctl.exe'
raw = subprocess.check_output([str(fixture)])
assert raw.isascii(), 'Status JSON must survive ANSI/OEM pipe decoding'
status = json.loads(raw)
assert status['backend'] == 2 and status['svmProbe']['asidCount'] == 64
assert status['nestedLastRefusalSiteText'] == '没有拒绝过'
assert status['svmProbe']['rejectReason'] == 8
assert status['svmProbe']['rejectReasonName'] == 'CR4_UNSUPPORTED_STATE'
assert status['svmProbe']['stateValidMask'] == 31
assert status['svmProbe']['cpuid1Ecx'] == '0x0C000000'
assert status['svmProbe']['xsaveFeatures'] == '0x00000008'
assert status['svmProbe']['cr4'] == '0x0000000000800000'
assert status['svmProbe']['xcr0'] == '0x0000000000000007'
assert status['svmProbe']['xss'] == '0x0000000000000800'
strings = subprocess.check_output([str(fixture), 'strings']).splitlines()
assert json.loads(strings[0]) == '没有拒绝过"\\\n\t😀'
assert json.loads(strings[1]) == '\ufffd\ufffd'
assert all(line.isascii() for line in strings)
commands = subprocess.check_output([str(cli), '--json', 'commands'])
assert commands.isascii()
# 期望条数从目录源码现算，不写死。
#
# 写死的 62 在远端加进 AMD 探针命令时没人同步，这个测试从那以后一直是红的，
# 而红得毫无信息量——它想守的是「JSON 输出与目录一致」，不是「目录恰好 62 条」。
EXPECTED_COMMANDS = len(re.findall(
    r'^\s*\{\s*"(?:\\.|[^"\\])*",\s*"(?:\\.|[^"\\])*",',
    (HERE / 'HvmCommandCatalog.c').read_text(encoding='utf-8-sig')
    .split('g_commands[] = {', 1)[1].split('\n};', 1)[0], re.M))
assert EXPECTED_COMMANDS > 0
assert len(json.loads(commands)['commands']) == EXPECTED_COMMANDS
metrics = json.loads(subprocess.check_output([str(fixture), 'metrics']))
assert metrics['version'] == 6 and metrics['backend'] == 2
general = metrics['svmProcessors'][0]['general']
assert general['valid'] == 1 and int(general['sequence']) == 0x100000002
assert int(general['preparedEntries']) == 13 and int(general['hardwareExits']) == 12
assert general['exitCode'] == '0xFEDCBA9876543210'
flight = metrics['svmProcessors'][0]['flight']
assert flight['coherent'] == 1 and flight['latched'] == 1
assert [int(r['ordinal']) for r in flight['rows']] == [0x100000002, 0x100000003]
assert flight['rows'][1]['exitCode'] == '0xFEDCBA9876543210'
assert len(flight['vmcb12Hex']) == 8192 and flight['vmcb12Hex'].endswith('A5')
assert len(flight['currentVmcbHex']) == 8192 and flight['currentVmcbHex'].startswith('5A')
assert metrics['svmProcessors'][0]['nestedProbe'] == {
    'valid': 1, 'sequence': 2, 'status': '0x00000000', 'entries': 1,
    'reflections': 1, 'faults': 7, 'exit': '0xFEDCBA9876543210',
    'marker': '0x000000004B534E31'}

# This actually crosses the native stdout -> PS 5.1 string pipeline which failed
# in the guest, with the Chinese legacy decoder explicitly selected.
script = """
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.Encoding]::GetEncoding(936)
$value = & '%s' | ConvertFrom-Json
if ($value.backend -ne 2 -or $value.nestedLastRefusalSiteText.Length -ne 5) { throw 'Status mismatch' }
$catalog = & '%s' --json commands | ConvertFrom-Json
if ($catalog.commands.Count -ne %d) { throw 'Catalog mismatch' }
'POWERSHELL_CP936_JSON=PASS'
""" % (str(fixture).replace("'", "''"), str(cli).replace("'", "''"),
       EXPECTED_COMMANDS)
result = subprocess.run(['powershell.exe', '-NoProfile', '-Command', script], capture_output=True)
assert result.returncode == 0, result.stderr
print(result.stdout.decode('ascii').strip())
print('QUERY_JSON_UTF8_ESCAPES=PASS (production formatter; simulated response only)')
