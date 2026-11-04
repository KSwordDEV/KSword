"""Verify startup enumeration and one-item lookup share actual backend fields."""
from pathlib import Path
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = r'''
#include "REGISTRY"
#include "STARTUP"
#include <fcntl.h>
#include <io.h>
static std::wstring scenario;
namespace ks::r3::startup {
StartupEnumerationResult EnumerateStartupSnapshot(const StartupEnumerationProgressCallback&, const StartupEnumerationStageResultCallback&) {
    StartupEnumerationResult result;result.success=true;
    StartupEntry e;e.uniqueIdText="source|id";e.category=StartupCategory::Registry;e.categoryText="Registry category";
    e.itemNameText="Item";e.registryValueNameText="display name";e.actionLocator.registryValueNameText="actual value";
    e.actionLocator.registryRoot=StartupRegistryRoot::LocalMachine;e.actionLocator.registrySubKeyText="Software\\Example";
    e.enabled=false;e.canDelete=true;e.deleteRegistryTree=true;e.detailText="real detail";result.entries.push_back(e);
    if(scenario==L"boot") {result.entries[0].actionKind=StartupActionKind::ScmStartType;result.entries[0].actionLocator.serviceStartMode=StartupScmStartMode::Boot;result.entries[0].actionLocator.serviceStartType=0;}
    if(scenario==L"incomplete")result.success=false;
    if(scenario==L"duplicate")result.entries.push_back(e);
    if(scenario==L"partial")result.sourceErrors.push_back({"WMI",5,false});
    return result;
}
ActionResult SetStartupEntryEnabled(const StartupEntry&,bool){return {};}
ActionResult DeleteStartupEntry(const StartupEntry&){return {};}
}
int wmain(int argc,wchar_t** argv){_setmode(_fileno(stdout),_O_U8TEXT);_setmode(_fileno(stderr),_O_U8TEXT);
    scenario=argv[1];++argv;--argc;ks::cli::registerStartupEnumeration();ks::cli::registerStartupActions();
    return ks::cli::dispatchR3(argc,argv).value_or(1);
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix="ksword-startup-detail-") as temp:
        directory = Path(temp)
        source = SOURCE.replace("REGISTRY", (ROOT / "KswordCLI/CommandRegistry.h").as_posix())
        source = source.replace("STARTUP", (ROOT / "shared/usermode/backend/startup/StartupEnumerator.h").as_posix())
        (directory / "fixture.cpp").write_text(source, encoding="utf-8")
        exe = directory / "fixture.exe"
        subprocess.run(["cl", "/nologo", "/std:c++20", "/EHsc", "/utf-8", "/O2", "/DNOMINMAX",
                        str(directory / "fixture.cpp"), str(ROOT / "KswordCLI/CommandRegistry.cpp"),
                        str(ROOT / "KswordCLI/R3Startup.cpp"), str(ROOT / "KswordCLI/R3StartupActions.cpp"),
                        "/Fe:" + str(exe), "/link", "Advapi32.lib"], cwd=directory, check=True)
        def run(scenario, *args, code=0):
            result = subprocess.run([str(exe), scenario, *args, "--json"], capture_output=True, timeout=10)
            assert result.returncode == code, (scenario, result.returncode, result.stdout, result.stderr)
            return json.loads(result.stdout)["data"]
        entry = run("normal", "startup", "enum")["entries"][0]
        assert entry["sourceUniqueId"] == "source|id" and entry["categoryDisplay"] == "Registry category"
        assert entry["displayRegistryValueName"] == "display name" and entry["registryValueName"] == "actual value"
        assert entry["deleteRegistryTree"] is True and entry["sourceEnabled"] is False
        assert entry["registryView"] is None and entry["disabledRegistrySubKey"] is None and entry["properties"] is None
        assert run("boot", "startup", "enum")["entries"][0]["serviceStartType"] == "0"
        selected = run("normal", "startup", "location", "query", "--id", entry["id"])
        assert selected == entry, (selected, entry)
        assert run("partial", "startup", "location", "query", "--id", entry["id"], code=6)["sourceUniqueId"] == "source|id"
        assert run("incomplete", "startup", "location", "query", "--id", entry["id"], code=6)["sourceUniqueId"] == "source|id"
        assert run("duplicate", "startup", "location", "query", "--id", entry["id"], code=3)["matchCount"] == "2"
    print("R3_STARTUP_DETAIL_PASS shared row, unknown fields, source failures and ambiguous identity")


if __name__ == "__main__":
    main()
