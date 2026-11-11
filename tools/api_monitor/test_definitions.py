"""Catalog completeness, rejected malformed inputs, deterministic incremental generation."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import generate_definitions as generator

root = Path(__file__).resolve().parents[2]
source = root / "APIMonitor_x64/api_monitor_definitions.json"
catalog = json.loads(source.read_bytes())
handlers = set(json.loads((source.parent / "hook/ApiHandlers.json").read_text()))
generator.validate(catalog, handlers)
legacy = [a for a in catalog["apis"] if a["id"] <= 614]
assert len(legacy) == 614 and {a["id"] for a in legacy} == set(range(1, 615))
assert sum(a["wrapper"]["kind"] == "generated" for a in legacy) == 411 - len([a for a in legacy if a["export"] in {"WSASendTo", "WSARecvFrom", "WSAIoctl"} and a["wrapper"]["kind"] == "special"])
# A frozen fingerprint of the original export identities, independent of new additions.
fingerprint = hashlib.sha256("\n".join(f"{a['id']}:{a['module']}:{a['export']}" for a in legacy).encode()).hexdigest()
assert fingerprint == "08620d889e24bd813b54a626fa75af0bfcb35dd87f481adbc49ff4c3ba46b73d"
mutations = [
    lambda c: c["apis"][1].update(id=c["apis"][0]["id"]),
    lambda c: c["apis"][1].update(module=c["apis"][0]["module"], export=c["apis"][0]["export"]),
    lambda c: c["apis"][0].update(return_type="HANDLE;system(1)"),
    lambda c: c["apis"][0].update(architectures=["arm64"]),
    lambda c: c["apis"][0].update(architectures=["x86", "x86"]),
    lambda c: c["apis"][0]["parameters"][0].update(type="Nonexistent"),
    lambda c: c["apis"][0]["parameters"][0].update(name="x);injected("),
    lambda c: c["apis"][0]["wrapper"].update(handler="UnknownHandler"),
    lambda c: c["apis"][0]["parameters"][0].update(length={"parameter": "missing", "unit": "bytes"}),
    lambda c: c["apis"][0]["parameters"][0].update(length={"parameter": c["apis"][0]["parameters"][0]["name"], "unit": "bytes"}),
    lambda c: next(a for a in c["apis"] if a["id"] == 641).update(extension_guid="invalid-guid"),
    lambda c: next(a for a in c["apis"] if a["id"] == 641).update(extension_guid=next(a["extension_guid"] for a in c["apis"] if a["id"] == 640)),
    lambda c: c["apis"][0]["parameters"][0].update(length={"parameter": "desiredAccess", "unit": "bytes", "indirect": True}),
]
def cyclic_lengths(c):
    first, second = c["apis"][0]["parameters"][1:3]
    for param, other in [(first, second), (second, first)]:
        param["type"] = "LPDWORD"
        param["length"] = {"parameter": other["name"], "unit": "elements", "indirect": True}
mutations.append(cyclic_lengths)
for change in mutations:
    invalid = copy.deepcopy(catalog)
    change(invalid)
    try:
        generator.validate(invalid, handlers)
    except ValueError:
        pass
    else:
        raise AssertionError("malformed catalog accepted")
with tempfile.TemporaryDirectory(prefix="ksword_definitions_") as temporary:
    directory = Path(temporary)
    digest = generator.generate(source, directory)
    before = {p.name: (p.stat().st_mtime_ns, p.read_bytes()) for p in directory.iterdir()}
    assert generator.generate(source, directory) == digest
    assert before == {p.name: (p.stat().st_mtime_ns, p.read_bytes()) for p in directory.iterdir()}
    assert digest == hashlib.sha256(source.read_bytes()).hexdigest()
    assert "HookedCreateFileW" in (directory / "ApiMonitorBindings.inc").read_text()
    assert "APIMON_SIMPLE" not in (directory / "ApiMonitorWrappers.inc").read_text()
    x86 = directory / "x86"
    assert generator.generate(source, x86, "x86") == digest
    assert (directory / "ApiMonitorDeclarations.inc").read_bytes() == (x86 / "ApiMonitorDeclarations.inc").read_bytes()
    assert "sizeof(ULONGLONG)" in (x86 / "ApiMonitorStackAbi.inc").read_text()
published = root / "Ksword5.1/x64/Release/profiles/api_monitor_definitions.json"
if published.exists():
    assert published.read_bytes() == source.read_bytes(), "published catalog must match successful build"
print("PASS: 614 legacy APIs, schema failures, deterministic generation and catalog identity")
