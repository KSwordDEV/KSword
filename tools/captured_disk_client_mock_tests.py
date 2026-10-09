"""使用生产Client封装与唯一内存运输mock；不连接控制设备或写实际磁盘。"""
from pathlib import Path
import subprocess

repo = Path(__file__).resolve().parents[1]
vc = Path("C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207")
sdk = Path("C:/Program Files (x86)/Windows Kits/10")
output = repo / ".codex-build-logs"
if not output.is_dir():
    raise RuntimeError("Existing build-log directory is required.")
args = [str(vc / "bin/Hostx64/x64/cl.exe"), "/nologo", "/std:c++20", "/Zc:__cplusplus", "/permissive-",
        "/utf-8", "/EHsc", "/MD", "/W4", "/WX", "/external:W0", "/DNOMINMAX", "/DWIN32_LEAN_AND_MEAN",
        "/DUNICODE", "/D_UNICODE", "/I" + str(vc / "include")]
for part in ("ucrt", "shared", "um"):
    args.append("/external:I" + str(sdk / "Include/10.0.26100.0" / part))
sources = [repo / "tools/captured_disk_client_mock_tests.cpp"]
sources += [repo / "Ksword5.1/Ksword5.1/ArkDriverClient" / (name + ".cpp")
            for name in ("ArkDriverStorageCapturedRead", "ArkDriverStorageCapturedWrite")]
objects = []
log = output / "captured-disk-client-mock.log"
log.write_text("", encoding="utf-8")

def run(command):
    result = subprocess.run(command, cwd=repo, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    text = result.stdout + result.stderr
    print(text, end="", flush=True)
    with log.open("a", encoding="utf-8") as stream:
        stream.write(text)
    if result.returncode:
        raise RuntimeError(f"Client mock failed with exit code {result.returncode}")

for source in sources:
    obj = output / (source.stem + "-mock.obj")
    run(args + ["/c", str(source), "/Fo" + str(obj)])
    objects.append(str(obj))
exe = output / "captured-disk-client-mock.exe"
link = [str(vc / "bin/Hostx64/x64/link.exe"), "/NOLOGO", "/SUBSYSTEM:CONSOLE", "/OUT:" + str(exe)]
link += ["/LIBPATH:" + str(vc / "lib/x64")]
link += ["/LIBPATH:" + str(sdk / "Lib/10.0.26100.0" / part / "x64") for part in ("ucrt", "um")]
run(link + objects)
run([str(exe)])
