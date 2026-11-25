"""离线验证网络证据草案的 JSON、二进制尾部和引用关系。"""

import json

from jsonschema import Draft202012Validator
from referencing import Resource

from check_base_v1 import FORMATS, REGISTRY, U64_MAX, check_equal, read_catalog


INLINE_LIMIT = 65_536  # RawRecord 二进制尾部字节上限。
METADATA_LIMIT = 1_536  # RawRecord 元数据 UTF-8 字节上限。
QUEUE_ROWS = 256  # 等待进入 Stored 块的记录数上限。
QUEUE_BYTES = 4 * 1024 * 1024  # 排队的二进制尾部总字节上限。


def raw_valid(validator, metadata, tail, metadata_bytes):
    """接收元数据、尾部和帧声明的元数据长度，返回结构及长度约束是否成立。"""
    encoded = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
    if not len(encoded) <= metadata_bytes <= METADATA_LIMIT or not validator.is_valid(metadata):
        return False
    if metadata["record"] == "loss":
        return (not tail
                and (int(metadata["queueDropped"]) > 0 or int(metadata["sourceLost"]) > 0
                     or metadata["sourceLossUnquantified"])
                and (not metadata["queueCounterSaturated"] or int(metadata["queueDropped"]) == U64_MAX)
                and (not metadata["sourceCounterSaturated"] or int(metadata["sourceLost"]) == U64_MAX))
    if metadata["record"] == "eof":
        return not tail

    # 端口和 PID 的确切范围，以及原长与实存长度的关系，由正文验证补足。
    for key in ("sourcePort", "destinationPort", "eventId"):
        if metadata[key] is not None and int(metadata[key]) > 65_535:
            return False
    original = None if metadata["originalLength"] is None else int(metadata["originalLength"])
    producer = int(metadata["producerCapturedLength"])
    captured = int(metadata["capturedLength"])
    if int(metadata["payloadPid"]) > (1 << 32) - 1 or captured != len(tail):
        return False
    if captured != min(producer, INLINE_LIMIT):
        return False
    if original is not None and (producer > original or (metadata["sourceTruncated"] and producer == original)):
        return False

    # 从捕获层和实际长度推导内容状态，读取者不能以元数据字段代替字节校验。
    if metadata["captureLayer"] == "flow-metadata":
        state = "metadata-only"
    elif metadata["sourceTruncated"] or captured < producer or (original is not None and captured < original):
        state = "truncated"
    elif original is None:
        state = "captured"
    elif original == 0:
        state = "no-payload"
    else:
        state = "complete"
    return state == metadata["payloadState"]


def link_valid(validator, link, resolved, raw):
    """接收出站链接和已解析的段、事件、来源及检查点，返回引用是否闭合。"""
    if not validator.is_valid(link):
        return False
    segment = resolved["segment"]  # 已核验段头身份。
    event = resolved["event"]  # 待确认的规范事件和来源字典投影。
    checkpoint = resolved["checkpoint"]  # 经外部解析的检查点覆盖信息。
    destination = resolved["destination"]  # 可供索引使用的目的地址。
    if (link["projectId"], link["sampleId"], link["rawSegmentOrdinal"]) != (
            segment["projectId"], segment["sampleId"], segment["ordinal"]):
        return False
    if (link["eventOrdinal"], link["rawRecordSequence"]) != (event["eventOrdinal"], event["primaryRawRecordSequence"]):
        return False
    for key in ("sourceId", "sourceEpoch", "processObjectId"):
        if raw[key] is None or raw[key] != event[key]:
            return False
    if (raw["direction"] != "2" or not int(raw["destinationAddress"], 16)
            or raw["destinationPort"] in (None, "0")
            or (raw["destinationAddress"], raw["destinationPort"]) != (destination["address"], destination["port"])):
        return False
    generation = link["checkpointGeneration"]  # null 代表尚无持久检查点证明。
    return generation is None or (generation == checkpoint["generation"]
                                  and checkpoint["coversRaw"] and checkpoint["coversEvent"])


def admission(case):
    """返回给定长度及队列占用下的预期接纳结果和实存字节数。"""
    producer = case["producerBytes"]  # 来源提供的完整字节数。
    if producer > INLINE_LIMIT and not case["retainPrefix"]:
        return "NeedsBlob", 0
    kept = min(producer, INLINE_LIMIT)  # 本记录需要从队列申请的字节数。
    if case["queuedRows"] >= QUEUE_ROWS or case["queuedPayloadBytes"] + kept > QUEUE_BYTES:
        return "QueueFull", 0
    return "Queued", kept


def main():
    """加载仓库固定向量，逐条比较验收值并打印通过数量。"""
    schema = read_catalog("network-evidence-draft.schema.json")
    vectors = read_catalog("vectors/network-evidence-draft.json")
    Draft202012Validator.check_schema(schema)
    registry = REGISTRY.with_resource(schema["$id"], Resource.from_contents(schema))
    raw_validator = Draft202012Validator(schema, registry=registry, format_checker=FORMATS)
    link_schema = {"$ref": f"{schema['$id']}#/$defs/verifiedOutboundLink"}
    link_validator = Draft202012Validator(link_schema, registry=registry, format_checker=FORMATS)

    # 先展开基础行，再物化测试中的内联字节。二进制正文不经过 JSON。
    flow = vectors["common"] | vectors["flow"]
    bases = {"common": vectors["common"], "flow": flow, "captured": flow | vectors["captured"]}
    for case in vectors["rawCases"]:
        metadata = bases[case["base"]] | case.get("set", {})
        tail = (bytes(i % 256 for i in range(case["inlineRepeat"])) if "inlineRepeat" in case
                else bytes.fromhex(case.get("inlineHex", "")))
        encoded_size = len(json.dumps(metadata, separators=(",", ":")).encode("utf-8"))
        valid = raw_valid(raw_validator, metadata, tail, case.get("metadataBytes", encoded_size))
        check_equal(valid, case["valid"], case["id"])

    # 接纳边界和跨流链接使用独立向量，避免把有效的 RawRecord 误计为已发布事件。
    for case in vectors["admissionCases"]:
        check_equal(admission(case), (case["outcome"], case["keptBytes"]), case["id"])
    for case in vectors["linkCases"]:
        resolved = {key: value | case.get(key, {}) for key, value in vectors["resolvedLink"].items()}
        link = vectors["outboundLink"] | case["set"]
        valid = link_valid(link_validator, link, resolved, flow | case.get("raw", {}))
        check_equal(valid, case["valid"], case["id"])
    total = sum(len(vectors[key]) for key in ("rawCases", "admissionCases", "linkCases"))
    print(f"PASS {total} network evidence contract vectors")


if __name__ == "__main__":
    main()
