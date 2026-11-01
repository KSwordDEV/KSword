"""Immutable Strong index preserves every binding identity without repeated normalization."""
from pathlib import Path
import json
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / "APIMonitor_x64/hook/HookTargets.cpp").read_text(encoding="utf-8-sig")
helpers = source[source.index("        std::wstring AnsiToWide("):source.index("        std::wstring NormalizeModuleNameForMatch(")]
lookup = source[source.index("        bool IsStrongTypedExport("):source.index("        bool IsUnsafeRawFallbackModule(")]
helpers = helpers.replace("return ToLowerWide(moduleName)", "++keyBuilds; return ToLowerWide(moduleName)")
apis = json.loads((root / "APIMonitor_x64/api_monitor_definitions.json").read_bytes())["apis"]
bindings = ",\n".join('{L"' + api["module"] + '","' + api["export"] + '"}' for api in apis)
code = r'''
#define NOMINMAX
#include <Windows.h>
#include <algorithm>
#include <cwctype>
#include <memory>
#include <string>
#include <unordered_set>
#include <cstdio>
static unsigned keyBuilds=0;
HELPERS
struct HookBinding {const wchar_t* moduleName; const char* procName;};
static HookBinding g_bindings[]={BINDINGS,{nullptr,nullptr}};
LOOKUP
#define CHECK(x) do{if(!(x)){printf("FAIL %d %s\n",__LINE__,#x);return 1;}}while(0)
int main(){
 CHECK(IsStrongTypedExport(L"KernelBase.dll","WriteFile"));
 const auto initial=keyBuilds;CHECK(initial==std::size(g_bindings));
 for(const auto& binding:g_bindings)if(binding.moduleName){
  auto module=std::wstring(binding.moduleName);auto api=std::string(binding.procName);
  CHECK(IsStrongTypedExport(module,api));
  std::transform(module.begin(),module.end(),module.begin(),::towupper);
  std::transform(api.begin(),api.end(),api.begin(),[](unsigned char c){return static_cast<char>(::toupper(c));});
  CHECK(IsStrongTypedExport(module,api));
 }
 CHECK(keyBuilds-initial==2*(std::size(g_bindings)-1));
 CHECK(!IsStrongTypedExport(L"other.dll","WriteFile"));
 CHECK(!IsStrongTypedExport(L"KernelBase","WriteFile")); // keep existing suffix semantics
 CHECK(!IsStrongTypedExport(L"KernelBase.dll","UnknownRawExport"));
 puts("PASS: 641 Strong identities/case rules preserved; each subsequent lookup normalizes one key");
}
'''.replace("HELPERS", helpers).replace("BINDINGS", bindings).replace("LOOKUP", lookup)
with tempfile.TemporaryDirectory(prefix="ksword_raw_identity_") as temporary:
    folder = Path(temporary)
    cpp = folder / "fixture.cpp"
    cpp.write_text(code, encoding="utf-8")
    subprocess.run(["cl", "/nologo", "/EHsc", "/std:c++17", "/utf-8", str(cpp),
                    "/Fe:" + str(folder / "fixture.exe"), "/Fo:" + str(folder / "fixture.obj")], check=True)
    subprocess.run([str(folder / "fixture.exe")], check=True, timeout=15)
