"""独立读取 C++ 夹具生成的离线项目，并核对文件字节与配置语义。"""

from hashlib import sha256
import json
from pathlib import Path
import re
import sys
from uuid import RFC_4122, UUID


FEATURE = "cli-offline-project-v1"


def fields(pairs):
    result = dict(pairs)
    assert len(result) == len(pairs), "duplicate key"
    return result


def uuid(text):
    value = UUID(text)
    assert str(value) == text and value.variant == RFC_4122 and value.int != 0
    assert UUID(bytes=bytes.fromhex(text.replace("-", ""))) == value


def load(path, keys, expected=None):
    raw = path.read_bytes()
    assert 0 < len(raw) <= 4 * 1024 * 1024 and raw.endswith(b"\n")
    assert b"\r" not in raw and not raw.startswith(b"\xef\xbb\xbf")
    digest = sha256(raw).hexdigest()
    if expected is not None:
        assert digest == expected, path
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=fields)
    assert set(value) == set(keys.split()), path
    print(f"{digest}  {path.relative_to(ROOT).as_posix()}")
    return value


def uint(text):
    assert isinstance(text, str) and re.fullmatch(r"0|[1-9][0-9]*", text)
    value = int(text)
    assert 0 <= value < 2**64
    return value


def quoted(text):
    return '"' + "".join(
        "\\u%04x" % ord(c) if ord(c) < 32 else "\\" + c if c in '\\"' else c for c in text
    ) + '"'


def config_hash(config):
    assert set(config) == {"title", "notes"}
    assert 0 < len(config["title"].encode("utf-8")) <= 1024
    assert len(config["notes"].encode("utf-8")) <= 65536
    raw = (r'{"notes":' + quoted(config["notes"]) + ',"title":' + quoted(config["title"]) + '}').encode("utf-8")
    return sha256(b"KSAA\0cli-offline-config-v1\0" + raw).hexdigest()


def check_manifest(name):
    doc = load(ROOT / name, "kind version requiredFeatures projectId title createdUtc currentRevisionId "
               "currentRevisionHash configSemanticHash journalGeneration journalHash catalogRoot producer storagePolicy")
    assert doc["kind"] == "action-analyze-project" and type(doc["version"]) is int and doc["version"] == 1
    assert doc["requiredFeatures"] == [FEATURE] and doc["producer"] == "KswordCLI"
    assert doc["storagePolicy"] == "local-ntfs-offline-metadata" and uint(doc["createdUtc"]) > 0
    uuid(doc["projectId"])
    uuid(doc["currentRevisionId"])
    return doc


def check():
    head = check_manifest("project.ksaproj")
    previous = check_manifest("journal/previous.ksaproj")
    project_id = head["projectId"]
    assert previous["projectId"] == project_id
    assert (head["journalGeneration"], previous["journalGeneration"]) == ("6", "4")
    generation, digest = head["journalGeneration"], head["journalHash"]
    chain = []
    committed = {}
    revisions = {}
    while uint(generation) != 0:
        commit = load(ROOT / "journal" / f"{generation}.json", "kind projectId generation previousGeneration "
                      "previousCommitHash operation changedId changedHash revisionId revisionHash configSemanticHash "
                      "catalogRoot", digest)
        assert commit["kind"] == "project-commit" and commit["projectId"] == project_id
        assert commit["generation"] == generation and uint(commit["previousGeneration"]) < uint(generation)
        uuid(commit["revisionId"])
        uuid(commit["changedId"])
        key = commit["revisionId"]
        if key not in revisions:
            revision = load(ROOT / "revisions" / f"{key}.json", "kind projectId revisionId parentRevisionId "
                            "parentRevisionHash configSemanticHash config", commit["revisionHash"])
            assert revision["kind"] == "offline-project-revision" and revision["projectId"] == project_id
            assert revision["revisionId"] == key and revision["configSemanticHash"] == config_hash(revision["config"])
            revisions[key] = (revision, commit["revisionHash"])
        revision, revision_hash = revisions[key]
        assert commit["configSemanticHash"] == revision["configSemanticHash"] and commit["revisionHash"] == revision_hash
        if not chain:
            assert head["currentRevisionId"] == key and head["currentRevisionHash"] == revision_hash
            assert head["catalogRoot"] == commit["catalogRoot"] and head["title"] == revision["config"]["title"]
        if commit["operation"] == "addSample":
            committed[commit["changedId"]] = commit["changedHash"]
        chain.append(uint(generation))
        generation, digest = commit["previousGeneration"], commit["previousCommitHash"]
    assert chain == [6, 4, 3, 2, 1] and digest is None
    assert len(committed) == 2 and len(revisions) == 3
    for key, (revision, _) in revisions.items():
        parent = revision["parentRevisionId"]
        if parent is None:
            assert revision["parentRevisionHash"] is None
        else:
            assert parent != key and revision["parentRevisionHash"] == revisions[parent][1]

    ref = head["catalogRoot"]
    assert set(ref) == {"generation", "hash"} and ref == previous["catalogRoot"] and ref["generation"] == "4"
    folder = ROOT / "catalog" / ref["generation"]
    catalog = load(folder / "manifest.json", "kind projectId generation sampleCount pageHashes", ref["hash"])
    assert catalog["kind"] == "sample-catalog" and catalog["projectId"] == project_id
    assert catalog["generation"] == "4" and catalog["sampleCount"] == "2" and len(catalog["pageHashes"]) == 1
    page = load(folder / "1.json", "kind projectId generation pageId samples", catalog["pageHashes"][0])
    assert page["kind"] == "sample-catalog-page" and page["projectId"] == project_id
    assert (page["generation"], page["pageId"]) == ("4", "1") and len(page["samples"]) == 2
    notes = []
    frozen_ids = set()
    for row in page["samples"]:
        summary = "sampleId title createdUtc revisionId snapshotId".split()
        assert set(row) == set([*summary, "descriptionHash"])
        for key in ("sampleId", "revisionId", "snapshotId"):
            uuid(row[key])
        assert uint(row["createdUtc"]) > 0 and row["descriptionHash"] == committed[row["sampleId"]]
        sample_dir = ROOT / "samples" / row["sampleId"]
        sample = load(sample_dir / "sample.json", " ".join(summary) + " kind projectId snapshotHash producer status "
                      "requestedBackend actualBackend initialTarget", row["descriptionHash"])
        assert all(sample[key] == row[key] for key in summary)
        assert sample["kind"] == "offline-sample" and sample["projectId"] == project_id
        assert sample["status"] == "not-collected" and sample["producer"] == "KswordCLI"
        assert all(sample[key] is None for key in ("requestedBackend", "actualBackend", "initialTarget"))
        snapshot = load(sample_dir / "snapshots" / (row["snapshotId"] + ".json"), "kind projectId sampleId snapshotId "
                        "revisionId revisionHash configSemanticHash config", sample["snapshotHash"])
        assert snapshot["kind"] == "offline-config-snapshot" and snapshot["projectId"] == project_id
        assert all(snapshot[key] == row[key] for key in ("sampleId", "snapshotId", "revisionId"))
        revision, raw_hash = revisions[snapshot["revisionId"]]
        assert snapshot["revisionHash"] == raw_hash and snapshot["config"] == revision["config"]
        assert snapshot["configSemanticHash"] == config_hash(snapshot["config"]) == revision["configSemanticHash"]
        frozen_ids.add(snapshot["revisionId"])
        notes.append(snapshot["config"]["notes"])
    assert notes == ['line 1\n\tline 2 "😀" / \\', '第二份配置'] and len(frozen_ids) == 2
    assert len(list((ROOT / "samples").iterdir())) == 3
    print(f"PROJECT_FORMAT=PASS FEATURE={FEATURE} JOURNAL={chain}")


if __name__ == "__main__":
    ROOT = Path(sys.argv[1]).resolve()
    check()
