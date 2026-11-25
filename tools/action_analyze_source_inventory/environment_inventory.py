"""Build and check the development-only RAV0 inventory using local text files."""

import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "docs/action-analyze-planning/environment"
DEFINITIONS = "APIMonitor_x64/api_monitor_definitions.json"
PROTOCOL = "shared/WinApiMonitorProtocol.h"
HOOKS = "APIMonitor_x64/hook/HookTargets.cpp"
GENERATOR = "tools/api_monitor/generate_definitions.py"
PLAN = "docs/ActionAnalyze反反虚拟机与环境实验行动方案.md"
HISTORICAL_REPORT = ".codex-build-logs/gui-per-api-vm-20261108/per-api-summary.json"
HISTORICAL_CAPTURE = "historical-api-matches.jsonl"
CATALOG = "environment-entry-catalog.jsonl"
OVERLAP = "rule-overlap.jsonl"
AREAS = {f"E{number:02}" for number in range(1, 17)}
ARCHITECTURES = ("x86", "x64")
KINDS = {"export", "com", "com-callback", "etw", "wmi-class", "wmi-notification", "kernel-callback",
         "ioctl", "instruction", "memory", "os-event", "callback", "host-inventory", "derived"}
FIELD_STATES = {"legacy-summary", "legacy-typed", "needs-capture", "needs-enrichment", "unsupported", "unknown"}
REPO_ANCHORS = {
    "registry-pre": ("KswordARKDriver/src/features/callback/registry_callback.c", "case RegNtPreQueryValueKey:"),
    "wmi-etw": ("Ksword5.1/Ksword5.1/MonitorDock/ProcessTraceMonitorWidget.Runtime.cpp", "Microsoft-Windows-WMI-Activity"),
    "dns-etw": ("Ksword5.1/Ksword5.1/MonitorDock/ProcessTraceMonitorWidget.Runtime.cpp", "Microsoft-Windows-DNS-Client"),
    "wmi-notification": ("Ksword5.1/Ksword5.1/MonitorDock/MonitorDock.cpp", "service->ExecNotificationQuery("),
    "host-firmware": ("Ksword5.1/Ksword5.1/HardwareDock/HardwareDock.cpp", "const UINT requiredSize = ::GetSystemFirmwareTable("),
    "syscall-evidence": ("shared/evidence/SyscallEvidence.h", "Classic PerfInfo SysCallEnter"),
}
REPORT_FIELDS = ("id", "module", "api", "baselineCalls", "monitoredCalls", "activeCalls", "events",
                 "matchedEvents", "verifiedSuccessCalls", "verifiedFailureCalls", "status",
                 "coverageStates", "coverageDetails", "skipReasons", "mismatches")
EXPECTED_REPORT_IDS = {653, 670, 673, 680, 798, 799, 800, 844}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_json(data):
    def unique_keys(pairs):
        result = dict(pairs)
        require(len(result) == len(pairs), "duplicate JSON key")
        return result

    return json.loads(data, object_pairs_hook=unique_keys)


def jsonl(rows):
    return "".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in rows).encode("utf-8")


def source_ref(path, needle):
    lines = (ROOT / path).read_text(encoding="utf-8-sig").splitlines()
    line = next((position for position, text in enumerate(lines, 1) if needle in text), None)
    require(line is not None, f"evidence anchor absent in {path}: {needle}")
    return {"path": path, "line": line, "anchor": needle}


def api_body_index():
    paths = sorted((ROOT / "APIMonitor_x64/hook").glob("*.inc")) + [ROOT / HOOKS]
    definitions = {}
    for path in paths:
        text = path.read_text(encoding="utf-8-sig")
        pattern = r"(?m)^[ \t]*[A-Za-z_][\w \t:*&]*?\b((?:Hooked|Capture)\w+)\([^;{]*?\)\s*\{"
        for match in re.finditer(pattern, text):
            symbol = match[1]
            require(symbol not in definitions, f"ambiguous implementation: {symbol}")
            definitions[symbol] = {
                "path": path.relative_to(ROOT).as_posix(),
                "line": 1 + text.count("\n", 0, match.start()),
                "anchor": symbol + "(",
            }
    return definitions


def raw_defaults():
    protocol = (ROOT / PROTOCOL).read_text(encoding="utf-8-sig")

    def strings(name):
        block = protocol.split(name + " =", 1)[1].split("\";", 1)[0] + '"'
        return "".join(re.findall(r'L"([^"]*)"', block)).casefold().split(";")

    return set(strings("kDefaultRawHookModules")), strings("kDefaultRawHookDenyList")


def default_raw_policy(module, export, modules, rules):
    module, export = module.casefold(), export.casefold()
    if module == "ntdll.dll":
        return "native-runtime-excluded"
    for pattern in rules:
        if (pattern.endswith("*") and export.startswith(pattern[:-1])) or export == pattern:
            return "default-deny:" + pattern
    if module in modules:
        return "listed-module-export-resolution-unverified"
    return "module-outside-default-list"


def project_history(data, declarations_sha, by_id):
    report = read_json(data)
    require(report["definitionSha256"] == declarations_sha, "historical report has a different definition SHA")
    require(report["catalogTotal"] == len(by_id) and report["focusDefinitions"] == 257 and not report["criticalFailures"],
            "unexpected historical report scope or critical failures")
    rows = []
    for architecture in ARCHITECTURES:
        for index, source in enumerate(report["architectures"][architecture]["apis"]):
            if source["id"] not in EXPECTED_REPORT_IDS:
                continue
            rows.append({"architecture": architecture, "reportPath": HISTORICAL_REPORT,
                         "reportSha256": sha256(data), "definitionSha256": declarations_sha,
                         "reportPointer": f"/architectures/{architecture}/apis/{index}",
                         "originalFields": {key: source[key] for key in REPORT_FIELDS}})
    return rows


def validate_history(rows, declarations_sha, by_id):
    result = {}
    digests = set()
    for index, row in enumerate(rows, 1):
        data = row["originalFields"]
        architecture, api_id = row["architecture"], data["id"]
        key = architecture, api_id
        require(key not in result and architecture in ARCHITECTURES and api_id in EXPECTED_REPORT_IDS,
                f"unexpected historical API row {key}")
        require(set(data) == set(REPORT_FIELDS), f"historical field mismatch for {key}")
        declaration = by_id[api_id]
        require(data["module"] == declaration["module"] and data["api"] == declaration["export"],
                f"historical identity mismatch for {key}")
        require(row["definitionSha256"] == declarations_sha and row["reportPath"] == HISTORICAL_REPORT,
                f"historical baseline mismatch for {key}")
        require(re.fullmatch(f"/architectures/{architecture}/apis/[0-9]+", row["reportPointer"]),
                f"bad historic report pointer for {key}")
        require(re.fullmatch(r"[0-9a-f]{64}", row["reportSha256"]), f"bad historic report digest for {key}")
        digests.add(row["reportSha256"])
        matched = data["matchedEvents"]
        require(matched == data["verifiedSuccessCalls"] + data["verifiedFailureCalls"] and not data["mismatches"],
                f"historical match count mismatch for {key}")
        if data["status"] == "verified":
            require(0 < matched <= min(data["activeCalls"], data["events"]), f"bad match count for {key}")
            state = "historical-return-matched"
        else:
            require(data["status"] == "hook_unavailable" and matched == 0, f"unexpected status for {key}")
            state = "historical-hook-unavailable"
        result[key] = {"state": state, "reference": f"{HISTORICAL_CAPTURE}#L{index}"}
    require(set(result) == {(arch, api_id) for arch in ARCHITECTURES for api_id in EXPECTED_REPORT_IDS}
            and len(digests) == 1, "historical evidence matrix is incomplete")
    return result


def phases(kind, direction, role):
    if kind in {"instruction", "etw", "memory", "os-event", "wmi-notification", "host-inventory", "derived"}:
        return ["observation"]
    if kind in {"com-callback", "callback"}:
        return ["observation"] if direction == "seen" else ["return"]
    if direction == "in":
        return ["entry"]
    if kind == "ioctl" and direction == "out":
        return ["return", "complete"]
    if role in {"dns-query-async"} and direction == "inout":
        return ["entry", "return", "complete"]
    return ["entry", "return"] if direction == "inout" else ["return"]


def strong_fields(api, role):
    fields = []
    for parameter in api["parameters"]:
        name = parameter["name"]
        direction = parameter["direction"]
        if api["export"] == "CoCreateInstance" and name == "objectPointer":
            direction = "out"
        if role == "registry-value-win32" and name == "dataSizePointer":
            direction = "inout"
        if api["export"] == "GetThreadContext" and name == "contextPointer":
            direction = "inout"
        phase = phases("export", direction, role)
        if api["export"] in {"DeviceIoControl", "NtDeviceIoControlFile", "NtFsControlFile"} and direction == "out":
            phase = ["return", "complete"]
        fields.append({"name": name, "type": parameter["type"], "role": direction, "phases": phase})
    return fields


def strong_rows(apis, implementation, history, api_digest):
    by_name = {}
    for index, api in enumerate(apis):
        by_name.setdefault(api["export"], []).append((index, api))
    selected = set()
    rows = []
    for line in (DATA / "strong-selection.jsonl").read_bytes().splitlines():
        group = read_json(line)
        require(set(group["fields"].values()) <= FIELD_STATES, f"bad field states in {group['role']}")
        for name in group["exports"].split():
            matches = by_name.get(name, [])
            require(len(matches) == 1 and name not in selected, f"missing/ambiguous/duplicate strong export {name}")
            selected.add(name)
            index, api = matches[0]
            wrapper = api["wrapper"]
            body = wrapper.get("handler") or wrapper["capture_handler"]
            require(body in implementation, f"implementation anchor absent for {body}")
            evidence = [{"path": DEFINITIONS, "jsonPointer": f"/apis/{index}", "sha256": api_digest}, implementation[body]]
            if wrapper["kind"] == "generated":
                evidence.append(source_ref(GENERATOR, "def wrapper(api):"))
            legacy_phases = ["return"]
            if name == "DeviceIoControl":
                legacy_phases += ["submit", "complete"]
                evidence.append(source_ref("APIMonitor_x64/core/MonitorAsyncIo.cpp", "void FinishIo("))
            coverage = {arch: history.get((arch, api["id"]), {"state": "unverified-in-inventory"})
                        for arch in api["architectures"]}
            rows.append({
                "id": f"api:{api['id']}", "areas": group["areas"], "kind": "export",
                "owner": api["module"], "symbol": name, "role": group["role"], "actorRole": "calling-thread",
                "architectures": api["architectures"],
                "contractFields": strong_fields(api, group["role"]), "returnType": api["return_type"],
                "declaration": api, "declarationState": "strong-defined", "sourceState": "legacy-wrapper-source",
                "legacyPhases": legacy_phases, "legacyProfileFields": group["fields"],
                "rawDefault": "strong-owns-identity", "runtimeEvidence": coverage, "evidence": evidence, "gap": group["gap"],
            })
    return rows


def additional_rows(apis, raw_modules, raw_rules):
    strong_symbols = {api["export"] for api in apis}
    rows = []
    with (DATA / "additional-entries.tsv").open(encoding="utf-8", newline="") as file:
        for row in csv.reader(file, delimiter="\t", quoting=csv.QUOTE_NONE):
            if row[0] == "areas":
                continue
            areas, kind, owner, symbol, role, synopsis, result, basis, gap = row
            require(kind in KINDS, f"bad source kind: {kind}")
            source_type, ref = basis.split(":", 1)
            if source_type == "repo":
                evidence = [source_ref(*REPO_ANCHORS[ref])]
                if kind == "kernel-callback":
                    evidence = [source_ref(REPO_ANCHORS[ref][0], f"case {symbol}:")]
                if ref == "syscall-evidence":
                    evidence.append(source_ref("Ksword5.1/Ksword5.1/MonitorDock/DirectKernelCallMonitorWidget.cpp", "constexpr GUID kPerfInfoGuid"))
            elif source_type == "plan":
                evidence = [source_ref(PLAN, "## " + ref + ".")]
            elif source_type == "url":
                require(ref.startswith("https://"), f"bad documentation URL for {symbol}")
                evidence = [{"url": ref}]
            else:
                path = {"ms": "windows/win32/api/", "wdk": "windows-hardware/drivers/ddi/"}[source_type]
                evidence = [{"url": "https://learn.microsoft.com/en-us/" + path + ref}]
            if kind == "export":
                require(symbol not in strong_symbols, f"reclassify newly defined export: {symbol}")
                evidence.append(source_ref(PROTOCOL, "kDefaultRawHookModules ="))
                evidence.append(source_ref(PROTOCOL, "kDefaultRawHookDenyList ="))
                raw_state = default_raw_policy(owner, symbol, raw_modules, raw_rules)
            else:
                raw_state = "not-applicable"
            fields = []
            for descriptor in [] if synopsis == "-" else synopsis.split("|"):
                direction, parameter = descriptor.split(" ", 1)
                name, native_type = parameter.split(":", 1)
                require(direction in {"in", "out", "inout", "seen"} and native_type and name,
                        f"invalid contract field for {symbol}: {descriptor}")
                fields.append({"name": name, "type": native_type, "role": direction,
                               "phases": phases(kind, direction, role)})
            source_state = "contract-candidate"
            legacy_phases = []
            if source_type == "repo":
                source_state = "legacy-separate-source"
                legacy_phases = ["entry"] if kind == "kernel-callback" else ["observation"]
            if kind == "derived":
                source_state = "derived-plan"
            actor_role = {
                "wmi-notification": "observer",
                "host-inventory": "observer",
                "etw": "provider-reported-actor-unresolved",
                "kernel-callback": "originating-thread",
                "ioctl": "requesting-thread",
                "derived": "analysis",
            }.get(kind, "target-side-candidate")
            rows.append({
                "id": f"{kind}:{owner}!{symbol}", "areas": areas.split(","), "kind": kind, "owner": owner,
                "symbol": symbol, "role": role, "actorRole": actor_role,
                "architectures": list(ARCHITECTURES), "contractFields": fields,
                "returnType": None if result == "-" else result, "declaration": None,
                "declarationState": "absent-from-strong" if kind == "export" else "not-an-agent-export",
                "sourceState": source_state, "legacyPhases": legacy_phases, "legacyProfileFields": {},
                "rawDefault": raw_state, "runtimeEvidence": {arch: {"state": "unverified-in-inventory"} for arch in ARCHITECTURES},
                "evidence": evidence, "gap": gap,
            })
    return rows


def validate_catalog(rows):
    ids = set()
    area_counts = Counter()
    for row in rows:
        row_id, areas = row["id"], row["areas"]
        require(row_id not in ids, f"duplicate inventory row {row_id}")
        ids.add(row_id)
        require(areas and len(set(areas)) == len(areas) and set(areas) <= AREAS, f"invalid surfaces for {row_id}")
        area_counts.update(areas)
        require(row["gap"] and row["evidence"] and row["contractFields"] is not None, f"incomplete row {row_id}")
        require(set(row["architectures"]) == set(row["runtimeEvidence"]), f"no architecture crosswalk for {row_id}")
        for field in row["contractFields"]:
            require(field["role"] != "out" or "entry" not in field["phases"], f"output treated as input in {row_id}")
        require(row["actorRole"], f"missing actor role: {row_id}")
        if row["declarationState"] != "strong-defined":
            require(all(item["state"] == "unverified-in-inventory" for item in row["runtimeEvidence"].values()),
                    f"new runtime proof attached to candidate {row_id}")
    require(set(area_counts) == AREAS, "E01–E16 coverage incomplete")
    return dict(sorted(area_counts.items()))


def validate_overlap(data, rows):
    """核对候选、来源锁及探测角色。输入排行仅保留字段名和定位。"""
    planning = DATA.parent
    local_path = planning / "local-candidates.jsonl"
    local_rows = [read_json(line) for line in local_path.read_bytes().splitlines()]
    local_by_id = {row["candidateId"]: row for row in local_rows}
    lock = read_json((planning / "source-lock.json").read_bytes())
    locked_commit = {row["sourceId"]: row["commit"] for row in lock["sources"]}
    tree_paths = sorted((planning / "upstream-files").glob("*.jsonl"))
    if not tree_paths:
        tree_paths = [planning / "upstream-files.jsonl"]
    overlap = [read_json(line) for line in data.splitlines()]
    paths_needed = {(row["source"]["sourceId"], row["source"]["path"]) for row in overlap if "path" in row["source"]}
    tree = {}
    for partition in tree_paths:
        for line in partition.read_bytes().splitlines():
            source = read_json(line)
            key = source["sourceId"], source["path"]
            if key in paths_needed:
                require(key not in tree, f"duplicate upstream file reference: {key}")
                tree[key] = source

    # 将字段施工建议连到目录角色。来源定位没有替代规则条件或运行证据。
    areas_by_role = {}
    for row in rows:
        areas_by_role.setdefault(row["role"], set()).update(row["areas"])
    for item in overlap:
        areas = set(item["areas"])
        for role in item["roles"]:
            require(areas & areas_by_role.get(role, set()), f"unresolved overlap role: {role}")
        source = item["source"]
        if source["sourceId"] == "ksword-sandbox":
            candidate = local_by_id[source["candidateId"]]
            require(candidate["jsonPointer"] == source["jsonPointer"] and source["fieldKeys"], "local candidate pointer mismatch")
        else:
            original = tree[(source["sourceId"], source["path"])]
            require(original["gitBlobSha"] == source["gitBlobSha"] and original["commit"] == locked_commit[source["sourceId"]],
                    "upstream candidate identity mismatch")
    return len(overlap)


def save_or_check(path, data, write):
    require(len(data.splitlines()) <= 2000, f"artifact exceeds 2000 lines: {path.name}")
    if write:
        if not path.exists() or path.read_bytes() != data:
            path.write_bytes(data)
    else:
        require(path.exists() and path.read_bytes() == data, f"stale or missing {path.name}. Rebuild with --write and review the diff.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate the catalog and check receipt in the inventory directory")
    parser.add_argument("--verify-history", action="store_true", help="also verify projection against the local archived report")
    parser.add_argument("--import-history", action="store_true", help="refresh historical projection from the fixed local report. Requires --write")
    args = parser.parse_args()
    require(not args.import_history or args.write, "--import-history requires --write")

    source = (ROOT / DEFINITIONS).read_bytes()
    source_sha = sha256(source)
    apis = read_json(source)["apis"]
    by_id = {api["id"]: api for api in apis}
    require(len(by_id) == len(apis), "duplicate definition ID")
    historical_path = DATA / HISTORICAL_CAPTURE
    if args.import_history or args.verify_history:
        projected = project_history((ROOT / HISTORICAL_REPORT).read_bytes(), source_sha, by_id)
        validate_history(projected, source_sha, by_id)
        save_or_check(historical_path, jsonl(projected), args.import_history)
    historical_bytes = historical_path.read_bytes()
    history = validate_history([read_json(line) for line in historical_bytes.splitlines()], source_sha, by_id)
    require(EXPECTED_REPORT_IDS <= {api["id"] for api in apis}, "historical references are outside the definitions")
    modules, denylist = raw_defaults()
    rows = strong_rows(apis, api_body_index(), history, source_sha) + additional_rows(apis, modules, denylist)
    rows.sort(key=lambda row: (row["areas"][0], row["kind"], row["owner"].casefold(), row["symbol"]))
    area_counts = validate_catalog(rows)
    require(EXPECTED_REPORT_IDS <= {row["declaration"]["id"] for row in rows if row["declaration"]},
            "historical projection contains unselected exports")
    overlap_bytes = (DATA / OVERLAP).read_bytes()
    overlaps = validate_overlap(overlap_bytes, rows)
    inventory_bytes = jsonl(rows)
    receipt = {
        "inventoryVersion": 1, "sourceDefinitionSha256": source_sha, "sourceDefinitionCount": len(apis),
        "rowCount": len(rows), "rowsByArea": area_counts,
        "ruleOverlapRows": overlaps,
        "legacyRaw": {
            "packetKind": "ApiCall",
            "resultKind": "EntryOnly",
            "phase": "entry",
            "registerSlots": {"x86": ["ECX", "EDX"], "x64": ["RCX", "RDX", "R8", "R9"]},
            "maximumStackSlots": 4,
            "pointeesCaptured": False,
            "typedResultCaptured": False,
            "evidence": [source_ref(HOOKS, "void RawHookEnter("), source_ref(HOOKS, "void DiscoverRawHookBindingsForLoadedModules()")],
        },
        "rowsByDeclarationState": dict(sorted(Counter(row["declarationState"] for row in rows).items())),
        "architectureEvidenceCounts": dict(sorted(Counter(item["state"] for row in rows
                                     for item in row["runtimeEvidence"].values()).items())),
        "dataSha256": {CATALOG: sha256(inventory_bytes), HISTORICAL_CAPTURE: sha256(historical_bytes), OVERLAP: sha256(overlap_bytes)},
    }
    receipt_bytes = (json.dumps(receipt, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    save_or_check(DATA / CATALOG, inventory_bytes, args.write)
    save_or_check(DATA / "inventory-check.json", receipt_bytes, args.write)
    print(f"PASS {len(rows)} inventory rows across {len(area_counts)} surfaces, {len(history)} historical architecture rows, {overlaps} locked-source joins")
    if args.verify_history:
        print("PASS historical projection matches the archived report")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError) as exc:
        sys.exit(f"ERROR: {exc}")
