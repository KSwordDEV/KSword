"""Start one isolated real MainWindow for source-matched GUI acceptance.

The runtime contains no driver/launcher, disables automatic R0/admin startup,
and has its own preferences. Operate only its explicitly enabled object bridge.
"""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import time
import argparse

root = Path(__file__).resolve().parents[2]
base = root / "output/noattach-v2-gui"
base.mkdir(exist_ok=True)
parser = argparse.ArgumentParser()
parser.add_argument('--reuse', type=Path)
parser.add_argument('--expected-sha', help='Exact artifact SHA from the successful build when reusing an older isolated runtime')
args = parser.parse_args()
runtime = args.reuse.resolve() if args.reuse else base / ("runtime-" + time.strftime("%Y%m%d-%H%M%S"))
source = root / "Ksword5.1/x64/Release"
if args.reuse:
    assert runtime.parent == base and runtime.name.startswith('runtime-')
    expected = args.expected_sha or hashlib.sha256((source / 'Ksword5.1.exe').read_bytes()).hexdigest()
    assert len(expected) == 64 and hashlib.sha256((runtime / 'Ksword5.1.exe').read_bytes()).hexdigest() == expected.lower()
else:
    runtime.mkdir(exist_ok=False)
    shutil.copy2(source / "Ksword5.1.exe", runtime / "Ksword5.1.exe")
    for dll in source.glob("*.dll"):
        shutil.copy2(dll, runtime / dll.name)
    for directory in ("platforms", "styles", "imageformats", "iconengines", "generic", "networkinformation", "tls", "translations", "languages"):
        if (source / directory).is_dir():
            shutil.copytree(source / directory, runtime / directory)
style = runtime / "style"
style.mkdir(exist_ok=True)
settings = {"prevent_multiple_instances": False, "startup_auto_request_admin": False,
            "startup_auto_install_r0_driver": False, "startup_scale_recommend_prompt_disabled": True,
            "dump_auto_check_enabled": False, "theme_mode": "light", "ui_language": "zh-CN"}
(style / "appearance_settings.json").write_text(json.dumps(settings, ensure_ascii=False, indent=2), encoding="utf-8")
assert not list(runtime.glob("*.sys")) and not (runtime / "Launcher.exe").exists()
target = subprocess.Popen([r"C:\Windows\System32\ping.exe", "-t", "127.0.0.1"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
with (base / "gui-stdout.log").open("wb") as log:
    main = subprocess.Popen([str(runtime / "Ksword5.1.exe"), "--mcp", "--mcp-no-auto-elevation"],
                            cwd=runtime, stdout=log, stderr=subprocess.STDOUT)
record = {"gui_pid": main.pid, "target_pid": target.pid, "runtime": str(runtime),
          "sha256": hashlib.sha256((runtime / "Ksword5.1.exe").read_bytes()).hexdigest()}
(base / "session.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
print(json.dumps(record), flush=True)
try:
    record['exit_code'] = main.wait()
finally:
    # Retain the exact child handles through acceptance; PID reuse cannot
    # redirect cleanup. The real GUI may also depend on its launcher lifetime.
    if target.poll() is None:
        target.terminate()
        target.wait(5)
    (base / 'session.json').write_text(json.dumps(record, indent=2), encoding='utf-8')
