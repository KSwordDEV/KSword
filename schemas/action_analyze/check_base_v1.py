"""Static A0 fixture checks. Read repository text and decode bytes in memory."""

import json
from hashlib import sha256
from pathlib import Path
from uuid import UUID

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parent
U64_MAX = (1 << 64) - 1
SIZES = {"u8": 1, "u16": 2, "u32": 4, "u64": 8, "uuid": 16}


class Invalid(ValueError):
    pass


def require(condition, issue):
    if not condition:
        raise Invalid(issue)


def check_equal(actual, expected, label):
    if actual != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")


def unique_object(pairs):
    obj = {}
    for key, val in pairs:
        require(key not in obj, "duplicateKey")
        obj[key] = val
    return obj


def read_catalog(name):
    return json.loads((ROOT / name).read_text(encoding="utf-8"), object_pairs_hook=unique_object)


FORMAT = read_catalog("archive-format.json")
LIMITS = FORMAT["limits"]
SCHEMAS = {name: read_catalog(name + ".schema.json") for name in ("value", "identity")}
REGISTRY = Registry().with_resources((schema["$id"], Resource.from_contents(schema)) for schema in SCHEMAS.values())
FORMATS = FormatChecker()


@FORMATS.checks("aa-u64", raises=ValueError)
def u64_format(value):
    return not isinstance(value, str) or (len(value) <= 20 and 0 <= int(value) <= U64_MAX)


@FORMATS.checks("aa-i64", raises=ValueError)
def i64_format(value):
    return not isinstance(value, str) or (len(value) <= 20 and -(1 << 63) <= int(value) < (1 << 63))


def validator(schema_name, definition=None):
    schema = SCHEMAS[schema_name]
    if definition:
        schema = {"$ref": f"{schema['$id']}#/$defs/{definition}"}
    return Draft202012Validator(schema, registry=REGISTRY, format_checker=FORMATS)


def validate_value(definition, value):
    require(validator("value", definition).is_valid(value), "schema")
    if definition == "range":
        limit = min(U64_MAX, 1 << value["pointerWidth"])
        require(int(value["base"], 16) + int(value["length"]) <= limit, "rangeEnd")
    elif definition == "bytes":
        require(int(value["offset"]) + int(value["length"]) <= U64_MAX, "blobEnd")
    elif definition == "fieldValue":
        if "value" in value:
            if value["type"] == "array":
                for item in value["value"]:
                    validate_value(value["itemType"], item)
            else:
                validate_value(value["type"], value["value"])
        if "rawRef" in value:
            validate_value("bytes", value["rawRef"])
        if "capturedLength" in value and "originalLength" in value:
            captured = int(value["capturedLength"])
            original = int(value["originalLength"])
            require(captured <= original and (value["state"] != "truncated" or captured < original), "captureLength")


def reject_number(_):
    raise Invalid("number")


def read_integer(text):
    require(len(text) <= 11, "number")
    result = int(text)
    require(-(1 << 31) <= result < (1 << 32), "number")
    return result


def check_json_tree(value, depth=0):
    if isinstance(value, (dict, list)):
        require(depth < LIMITS["jsonDepth"], "depth")
    if isinstance(value, dict):
        for key, item in value.items():
            check_json_tree(key, depth + 1)
            check_json_tree(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            check_json_tree(item, depth + 1)
    elif isinstance(value, str):
        require(len(value.encode("utf-8", errors="strict")) <= LIMITS["jsonStringUtf8Bytes"], "stringLength")


def parse_json_object(raw):
    require(len(raw) <= LIMITS["jsonBytes"], "jsonLength")
    require(not raw.startswith(b"\xef\xbb\xbf"), "bom")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=unique_object,
                           parse_int=read_integer, parse_float=reject_number, parse_constant=reject_number)
        require(isinstance(value, dict), "object")
        check_json_tree(value)
    except UnicodeError as error:
        raise Invalid("utf8") from error
    except json.JSONDecodeError as error:
        raise Invalid("syntax") from error
    except RecursionError as error:
        raise Invalid("depth") from error
    return value


def canonical_json(value):
    if isinstance(value, str):
        chars = []
        for char in value:
            if ord(char) < 32:
                chars.append(f"\\u{ord(char):04x}")
            else:
                chars.append("\\" + char if char in ('"', "\\") else char)
        return '"' + "".join(chars) + '"'
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: key.encode("utf-8"))
        return "{" + ",".join(canonical_json(key) + ":" + canonical_json(value[key]) for key in keys) + "}"
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    return json.dumps(value)


def object_key(ref):
    return ref["sampleId"], ref["objectId"]


def check_observation(item, ledger):
    require(validator("identity").is_valid(item), "identitySchema")
    basis = item["basis"]
    require(int(basis["firstReceiveQpc"]) <= int(basis["lastReceiveQpc"]), "observationInterval")
    if item["kind"] == "thread" and "owner" in item:
        owner = item["owner"]
        require(owner["sampleId"] == item["ref"]["sampleId"], "ownerSample")
        resolved = ledger.get(object_key(owner))
        require(resolved is not None and resolved["kind"] == "process", "ownerKind")
        if item["strength"] == "strong":
            require(resolved["strength"] == "strong", "ownerStrength")


def compare_instances(left, right, ledger):
    if left["kind"] != right["kind"]:
        return "distinct"
    if left["kind"] == "process":
        keys = ("machineId", "bootId", "pid", "createTime100ns")
        owner = "confirmed"
    else:
        keys = ("tid", "createTime100ns")
        owner = "candidate"
        if "owner" in left and "owner" in right:
            owner = compare_instances(ledger[object_key(left["owner"])], ledger[object_key(right["owner"])], ledger)
    if owner == "distinct" or any(key in left and key in right and left[key] != right[key] for key in keys):
        return "distinct"
    if left["strength"] == right["strength"] == "strong" and owner == "confirmed":
        return "confirmed"
    return "candidate"


def head_fields(layout, data, layer):
    require(len(data) >= layout["bytes"], "truncated")
    result = {}
    for field in layout["fields"]:
        pos = field["offset"]
        kind = field["type"]
        size = field.get("bytes", SIZES.get(kind))
        raw = data[pos:pos + size]
        if kind == "uuid":
            result[field["name"]] = str(UUID(bytes=raw))
        elif kind == "bytes":
            result[field["name"]] = raw
        else:
            result[field["name"]] = int.from_bytes(raw, "little")
        if "constHex" in field:
            require(raw.hex() == field["constHex"], layer + ".magic")
        if "crcOverHeaderBytes" in field:
            domain = field["crcOverHeaderBytes"]
            start = domain["offset"]
            require(result[field["name"]] == crc32c(data[start:start + domain["bytes"]]), layer + ".headerCrc")
    for field in layout["fields"]:
        name = field["name"]
        value = result[name]
        if "const" in field:
            require(value == field["const"], layer + "." + name)
        if "allowedMask" in field:
            require(not value & ~field["allowedMask"], layer + "." + name)
        if field.get("allZero"):
            require(not any(value), layer + "." + name)
    return result


def crc32c(data):
    crc = 0xFFFFFFFF
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def payload_json(data, issue):
    try:
        return parse_json_object(data)
    except Invalid as error:
        raise Invalid(issue) from error


def decode_record_payload(record, payload):
    result = {key: record[key] for key in ("recordType", "recordSchemaVersion", "flags")}
    if record["recordSchemaVersion"] != 1:
        return None
    if record["recordType"] == FORMAT["recordTypeIds"]["RawRecord"]:
        require(len(payload) >= 4, "raw.length")
        json_bytes = int.from_bytes(payload[:4], "little")
        require(json_bytes <= len(payload) - 4, "raw.length")
        result["metadataJson"] = payload_json(payload[4:4 + json_bytes], "raw.json")
        result["inlineRawHex"] = payload[4 + json_bytes:].hex()
    elif record["recordType"] == FORMAT["recordTypeIds"]["CanonicalEvent"]:
        layout = FORMAT["canonicalEventCoreV1"]
        require(len(payload) >= 128, "event.length")
        core = head_fields(layout, payload[:128], "event")
        require(len(payload) == 128 + core["fieldJsonBytes"], "event.length")
        for field in layout["fields"]:
            name = field["name"]
            if "min" in field:
                require(core[name] >= field["min"], "event.requiredRef")
            if "validityBit" in field:
                if core["validityBits"] & (1 << field["validityBit"]):
                    require(core[name] >= field.get("minWhenValid", 0), "event.validityValue")
                else:
                    require(core[name] == 0, "event.validityValue")
                    core[name] = None
            if field["type"] == "u64" and core[name] is not None:
                core[name] = str(core[name])
        result["core"] = core
        result["fieldJson"] = payload_json(payload[128:], "event.json")
    else:
        return None
    return result


def scan_segment(data, identity, check_payloads=True):
    position = 0
    blocks = []
    payloads = []
    opaque_optional = 0
    raw_only = False
    previous_block = previous_seq = -1
    try:
        require(len(data) <= LIMITS["segmentBytes"], "segment.limit")
        seg = head_fields(FORMAT["segmentHeader"], data[:96], "segment")
        require(seg["streamKind"] in FORMAT["streamKinds"].values(), "segment.stream")
        require(seg["segmentOrdinal"] >= FORMAT["minimumSegmentOrdinal"], "segment.ordinal")
        require(all(str(seg[key]) == str(value) for key, value in identity.items()), "segment.identity")
        position = 96
        while position < len(data):
            block = head_fields(FORMAT["blockHeader"], data[position:position + 80], "block")
            stored = block["storedBytes"]
            decoded = block["decodedBytes"]
            count = block["recordCount"]
            require(0 < stored <= LIMITS["blockStoredBytes"] and decoded <= LIMITS["blockDecodedBytes"], "block.length")
            require(LIMITS["minBlockRecordCount"] <= count <= LIMITS["maxBlockRecordCount"] and count <= decoded // 32,
                    "block.recordCount")
            require(block["blockOrdinal"] > previous_block, "block.ordinal")
            first, last = block["firstRecordSequence"], block["lastRecordSequence"]
            require(first > previous_seq and last >= first and last - first >= count - 1, "block.sequence")
            if block["flags"] & 1:
                require(block["minReceiveQpc"] <= block["maxReceiveQpc"], "block.qpcRange")
            if block["codec"] == FORMAT["codecIds"]["Stored"]:
                require(stored == decoded, "block.length")
            end = position + 80 + stored
            require(end <= len(data), "truncated")
            require(block["codec"] in FORMAT["subsetCodecs"], "block.codec")
            body = data[position + 80:end]
            check = crc32c(body)
            require(check == block["storedCRC32C"], "block.storedCrc")
            require(check == block["decodedCRC32C"], "block.decodedCrc")
            offset = 0
            staged_payloads = []
            staged_optional = 0
            staged_raw_only = False
            for index in range(count):
                require(len(body) - offset >= 32, "record.length")
                record = head_fields(FORMAT["recordHeader"], body[offset:offset + 32], "record")
                total = record["totalBytes"]
                require(32 <= total <= len(body) - offset and total - 32 == record["payloadBytes"], "record.length")
                seq = record["recordSequence"]
                require(seq > previous_seq and (index > 0 or seq == first) and (index < count - 1 or seq == last),
                        "record.sequence")
                payload = body[offset + 32:offset + total]
                require(crc32c(payload) == record["payloadCRC32C"], "record.payloadCrc")
                if check_payloads:
                    projected = decode_record_payload(record, payload)
                    if projected is not None:
                        staged_payloads.append(projected)
                    elif record["flags"] & 1:
                        staged_raw_only = True
                    else:
                        staged_optional += 1
                offset += total
                previous_seq = seq
            require(offset == len(body), "block.trailingBytes")
            previous_block = block["blockOrdinal"]
            position = end
            description = {"ordinal": str(previous_block), "firstSequence": str(first), "lastSequence": str(last), "endOffset": end}
            if block["flags"] & 1:
                for key in ("minReceiveQpc", "maxReceiveQpc"):
                    description[key] = str(block[key])
            blocks.append(description)
            payloads.extend(staged_payloads)
            opaque_optional += staged_optional
            raw_only |= staged_raw_only
    except Invalid as error:
        status = str(error)
    else:
        status = "raw-only" if raw_only else "complete"
    return {"status": status, "prefixBytes": position, "blocks": blocks, "payloads": payloads, "opaqueOptional": opaque_optional}


def accepted(action):
    try:
        action()
    except Invalid:
        return False
    return True


def check_base_vectors():
    vectors = read_catalog("vectors/base-v1.json")
    for case in vectors["values"]:
        check_equal(accepted(lambda: validate_value(case["def"], case["value"])), case["valid"], case["id"])
    for case in vectors["json"]:
        raw = case["input"].encode("utf-8") if "input" in case else bytes.fromhex(case["inputHex"])
        try:
            value = parse_json_object(raw)
        except Invalid as error:
            check_equal(str(error), case.get("error"), case["id"])
            continue
        check_equal(case.get("error"), None, case["id"])
        canonical = canonical_json(value).encode("utf-8")
        check_equal(canonical.hex(), case["canonicalHex"], case["id"])
        for domain, expected in case["semanticSha256"].items():
            hashed = sha256(b"KSAA\0" + domain.encode("ascii") + b"\0" + canonical).hexdigest()
            check_equal(hashed, expected, domain)
    identity = vectors["identity"]
    sample = identity["sampleId"]
    observations = {}
    ledger = {}
    for name, spec in identity["observations"].items():
        item = {key: val for key, val in spec.items() if key not in {"objectId", "ownerId", "valid"}}
        item.update(ref={"sampleId": sample, "objectId": spec["objectId"]}, basis=identity["basis"])
        if "ownerId" in spec:
            item["owner"] = {"sampleId": sample, "objectId": spec["ownerId"]}
        valid = accepted(lambda: check_observation(item, ledger))
        check_equal(valid, spec.get("valid", True), name)
        if valid:
            observations[name] = item
            ledger[object_key(item["ref"])] = item
    for case in identity["matchCases"]:
        left, right = (observations[name] for name in case["pair"])
        check_equal(compare_instances(left, right, ledger), case["expected"], case["id"])
    for case in identity["referenceCases"]:
        value = dict(case["value"])
        if case.get("withSample"):
            value["sampleId"] = sample
        valid = validator("identity", case["def"]).is_valid(value)
        if valid and case["def"] == "roles":
            for key, ref in value.items():
                if isinstance(ref, dict):
                    kind = "process" if key.endswith("Process") else "thread"
                    valid &= (ref["sampleId"] == sample and ledger.get(object_key(ref), {}).get("kind") == kind)
        check_equal(valid, case["valid"], case["id"])
    return sum(len(group) for group in [vectors["values"], vectors["json"], *[identity[key] for key in ("observations", "matchCases", "referenceCases")]])


def check_stored_vectors():
    vectors = read_catalog("vectors/stored-v1.json")
    check_equal(FORMAT["version"], vectors["formatVersion"], "archive version")
    known_crc = vectors["crcCheck"]
    crc = crc32c(bytes.fromhex(known_crc["inputHex"]))
    check_equal(f"{crc:08x}", known_crc["integerHex"], "CRC-32C standard check")
    check_equal(crc.to_bytes(4, "little").hex(), known_crc["littleEndianHex"], "CRC byte order")
    fixtures = {}
    for name, spec in vectors["fixtures"].items():
        fixture = bytes.fromhex("".join(spec["hex"]))
        check_equal(len(fixture), spec["bytes"], name)
        check_equal(sha256(fixture).hexdigest(), spec["sha256"], name)
        fixtures[name] = fixture
    for case in vectors["cases"]:
        spec = vectors["fixtures"][case["base"]]
        fixture = bytearray(fixtures[case["base"]][:case.get("take")])
        if "append" in case:
            fixture.extend(fixtures[case["append"]])
        if "appendHex" in case:
            fixture.extend(bytes.fromhex(case["appendHex"]))
        for offset, hex_bytes in case.get("patch", []):
            raw = bytes.fromhex(hex_bytes)
            require(offset + len(raw) <= len(fixture), "fixture patch out of bounds")
            fixture[offset:offset + len(raw)] = raw
        identity = vectors["expectedIdentity"] | {"streamKind": spec["streamKind"]}
        fixture = bytes(fixture[:case.get("truncate")])
        result = scan_segment(fixture, identity)
        for key in ("status", "prefixBytes"):
            check_equal(result[key], case[key], f"{case['id']} {key}")
        check_equal(len(result["blocks"]), case["blocks"], case["id"])
        check_equal(result["opaqueOptional"], case.get("opaqueOptional", 0), case["id"])
        framing = scan_segment(fixture, identity, check_payloads=False)
        check_equal(framing["prefixBytes"], case.get("framedBytes", case["prefixBytes"]), f"{case['id']} framed prefix")
        if set(case) == {"id", "base", "prefixBytes", "blocks", "status"}:
            header = head_fields(FORMAT["segmentHeader"], fixture, "segment")
            check_equal(str(header["createdUtc100ns"]), vectors["expectedCreatedUtc100ns"], case["id"])
            check_equal(result["blocks"], spec["expectedBlocks"], case["id"])
            check_equal(result["payloads"], [spec["expectedPayload"]], case["id"])
    return len(vectors["cases"])


def check_catalogs():
    for schema in SCHEMAS.values():
        Draft202012Validator.check_schema(schema)
    for name in ("segmentHeader", "blockHeader", "recordHeader", "canonicalEventCoreV1"):
        layout = FORMAT[name]
        cursor = 0
        for field in layout["fields"]:
            check_equal(field["offset"], cursor, f"{name}.{field['name']}")
            cursor += field.get("bytes", SIZES.get(field["type"]))
        check_equal(cursor, layout["bytes"], name)
    uuid_spec = FORMAT["uuidByteOrder"]
    check_equal(UUID(uuid_spec["canonicalText"]).bytes.hex(), uuid_spec["expectedHex"], "canonical UUID bytes")
    check_equal(UUID(uuid_spec["canonicalText"]).bytes_le.hex(), uuid_spec["invalidWindowsGuidMemoryHexForThisText"], "GUID memory bytes")
    catalog = read_catalog("field-catalog.json")
    ids = set()
    for field in catalog["fields"]:
        require(field["fieldId"] not in ids, "duplicate fieldId")
        ids.add(field["fieldId"])
        schema, definition = field["type"].split("#/$defs/")
        require(definition in SCHEMAS[schema.removesuffix(".schema.json")]["$defs"], "unknown field type")
        for attr, table in (("phaseSet", "phaseSets"), ("sourceSet", "sourceSets"),
                            ("availability", "availability"), ("textProfile", "textProfiles")):
            require(field[attr] in catalog[table], "unregistered " + attr)
        require(field["unit"] and field["maxValueJsonBytes"] > 0, "invalid field bounds")
    return len(ids)


if __name__ == "__main__":
    fields = check_catalogs()
    base_cases = check_base_vectors()
    stored_cases = check_stored_vectors()
    print(f"A0 base v1: {fields} catalog fields, {base_cases} value/identity/JSON cases, {stored_cases} Stored cases plus CRC/UUID checks passed.")
