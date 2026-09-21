"""Independently verify exported bounded-probe evidence; never execute a driver."""
import argparse
import hashlib
import json
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    raw = path.read_bytes()
    # Windows PowerShell Tee-Object uses UTF-16; CLI and explicit exports use UTF-8.
    encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
    return json.loads(raw.decode(encoding))


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify(root, candidate):
    root = root.resolve()
    export = read(root / "export-manifest.json")
    names = set()
    for item in export["files"]:
        path = (root / item["path"]).resolve()
        require(path.is_relative_to(root) and path not in names, "Invalid/duplicate export path")
        names.add(path)
        require(path.stat().st_size == item["bytes"] and
                digest(path) == item["sha256"].lower(), f"Export mismatch: {path.name}")

    def evidence(name):
        path = root / name
        require(path.resolve() in names, f"Evidence not in export manifest: {name}")
        return read(path)

    identity = evidence("identity.json")
    for name in ("KswordARK.sys", "KswordARK.pdb", "hvm_ctl.exe"):
        require(digest(candidate / name) == identity["candidateSha256"][name].lower(),
                f"Candidate identity mismatch: {name}")
    loads = list(root.glob("driver-load-*/result.json"))
    require(len(loads) == 1, "Expected exactly one driver-load result")
    loaded = evidence(str(loads[0].relative_to(root)))
    require(loaded["result"] == "PASS" and loaded["signature"] == 0, "Driver load/signature failed")
    guest = evidence("guest.json")
    count, cycles = guest["cpuCount"], guest["cycles"]
    require(count in (1, 2, 4, 8) and 0 < cycles <= 1000, "Unexpected probe dimensions")
    require(guest["kind"] == "bounded-svm-nested-probe" and guest["hardwareResult"] == "PASS",
            "No completed bounded probe")
    require(guest["ctlHash"].lower() == identity["candidateSha256"]["hvm_ctl.exe"].lower(),
            "Executed CLI differs from candidate")
    journal_path = root / "controls.jsonl"
    require(journal_path in names, "Missing control journal")
    journal = [json.loads(line) for line in journal_path.read_text(encoding="utf-8-sig").splitlines()]
    verbs = (["status", "prepare-svm-probe", "status"] +
             ["self-test-svm-nested", "status", "metrics"] * cycles + ["teardown", "status"])
    require(len(journal) == 2 * len(verbs) + 1 and journal[-1]["phase"] == "complete" and
            journal[-1]["result"] == "PASS", "Incomplete/extra journal controls")
    responses = []
    for index, verb in enumerate(verbs, 1):
        before, after = journal[(index - 1) * 2:index * 2]
        require(before["phase"] == "before" and before["id"] == index and before["command"] == verb
                and after["phase"] == "after" and after["id"] == index and after["exitCode"] == 0,
                f"Control ordering/failure at {index}")
        row = evidence(f"{index:05}-{verb}.json")
        if row["kind"] == "control":
            require(row["status"] == 0 and row["lastStatus"] == "0x00000000", "Control failed")
        responses.append(row)
    expected = {(0, number) for number in range(count)}
    epoch = responses[2]["powerGeneration"]
    previous = {cpu: 0 for cpu in expected}
    faults = {cpu: [] for cpu in expected}
    for cycle in range(cycles):
        control, status, metrics = responses[3 + 3 * cycle:6 + 3 * cycle]
        require(control["failedProcessorCount"] == 0 and control["selfTestPassedProcessorCount"] == count,
                "Incomplete per-CPU test")
        require(status["backend"] == 2 and status["queryStatus"] == 0 and
                status["powerGeneration"] == epoch and status["preparedProcessorCount"] == count and
                status["selfTestPassedProcessorCount"] == count and status["residentProcessorCount"] == 0
                and status["generation"] == control["newGeneration"], "Invalid status/generation")
        rows = status["processors"]
        require(len(rows) == count and {(r["group"], r["number"]) for r in rows} == expected,
                "Wrong status CPU set")
        require(all("SELF_TESTED" in r["stateNames"] and r["lastStatus"] == "0x00000000" for r in rows),
                "CPU status did not acknowledge completion")
        require(not ({"FAULTED", "ROLLBACK_REQUIRED"} & set(status["stateNames"])), "Fault retained")
        rows = metrics["svmProcessors"]
        require(metrics["version"] in (4, 5, 6) and metrics["backend"] == 2 and len(rows) == count and
                {(r["group"], r["number"]) for r in rows} == expected, "Wrong metrics version/CPU set")
        for row in rows:
            cpu = row["group"], row["number"]
            probe = row["nestedProbe"]
            require(probe["valid"] == 1 and probe["status"] == "0x00000000" and
                    probe["sequence"] > previous[cpu] and probe["sequence"] % 2 == 0 and
                    probe["entries"] == probe["reflections"] == 1 and probe["faults"] > 0 and
                    int(probe["exit"], 16) == 0x72 and int(probe["marker"], 16) == 0x4B534E31 and
                    row["generation"] == status["generation"] and row["failureStatus"] == "0x00000000",
                    f"Invalid completion: cycle={cycle + 1}, cpu={cpu}")
            previous[cpu] = probe["sequence"]
            faults[cpu].append(probe["faults"])
    final = responses[-1]
    require(final["stateFlags"] == 1 and final["preparedProcessorCount"] == 0 and
            final["residentProcessorCount"] == 0 and final["slatReady"] == 0 and
            final["powerGeneration"] == epoch, "Incomplete release or power change")
    return dict(result="PASS", scope="bounded-svm-nested-probe", vcpu=count, cycles=cycles,
                filesVerified=len(names), completedCpuRoundTrips=count * cycles, released=True,
                innerOperatingSystemTested=False, concurrentInnerVcpusTested=False,
                rsds=identity["rsds"], exportManifestSha256=digest(root / "export-manifest.json"),
                processors=[dict(group=g, number=n, finalSequence=previous[g, n],
                                 npfMin=min(faults[g, n]), npfMax=max(faults[g, n])) for g, n in sorted(expected)])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = json.dumps(verify(args.evidence, args.candidate), indent=2) + "\n"
    args.output.write_text(report, encoding="utf-8")
    print(report)
