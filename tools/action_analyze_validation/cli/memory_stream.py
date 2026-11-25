"""Exercise the official Release CLI against the existing owned memory fixture."""

import hashlib
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

from memory_watch import CLI, analyze, check, read_record, read_records


def records(proc):
    output = queue.Queue()
    threading.Thread(target=read_records, args=(proc.stdout, output), daemon=True).start()
    return output


def send(proc, command):
    proc.stdin.write(command + "\n")
    proc.stdin.flush()


def open_stream(options):
    return subprocess.Popen([str(CLI), "analyze", "memory", "stream", *options, "--confirm", "--output", "jsonl"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW)


def assert_summary(proc, output, start, reason, state, code, observed=None):
    while True:
        frame = read_record(output)
        check(frame["captureId"] == start["captureId"] and frame["trackingEpoch"] == start["trackingEpoch"], frame)
        if frame["type"] != "round":
            break
        if observed is not None:
            observed.append(frame["data"])
    data = frame["data"]
    check(frame["type"] == "summary" and data["reason"] == reason and data["state"] == state and
          data["exitCode"] == code, frame)
    check(output.get(timeout=10) is None and proc.wait(timeout=10) == code,
          f"Stream did not close with exit {code}")
    return data


def check_finite(options):
    for command, rows_field in (("watch", "observations"), ("track", "rounds")):
        args = ["analyze", "memory", command, *options, "--samples", "2", "--json"]
        if command == "track":
            args.append("--confirm")
        result = subprocess.run([str(CLI), *args], capture_output=True, timeout=15,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        check(result.returncode == 0, f"Bounded {command} failed: {result.stderr!r}")
        reply = json.loads(result.stdout)
        data = reply["data"]
        check(reply["backend"] == "r3" and data["complete"], f"Bounded {command} failed: {reply}")
        rows = data[rows_field]
        check(len(rows) == 2, f"Expected 2 bounded {command} rows")
        if command == "watch":
            check(rows[0]["difference"] is None and int(rows[1]["difference"]["changedByteCount"]) == 0,
                  "Bounded watch lost its baseline or unchanged observation")
        else:
            page = rows[1]["pages"][0]
            check(type(rows[1]["ordinal"]) is int and rows[1]["ordinal"] == 2 and page["content"]["version"] == 1
                  and page["content"]["origin"] == "unchanged" and page["difference"]["changedBytes"] == 0,
                  "Bounded track lost its numeric counters or unchanged observation")
    print("PASS bounded watch and track: two samples, single JSON document each")


def check_stream(options, target, target_records, seed):
    with open_stream(options) as proc:
        try:
            output = records(proc)
            start = read_record(output)
            check(start["type"] == "start" and start["data"]["state"] == "active" and
                  int(start["data"]["observedCreationFileTime"]) == seed["creation"], "Stream start mismatch")

            ordinal = 0
            changes = 0

            def observe(message):
                nonlocal ordinal, changes
                check(message["type"] == "round" and message["captureId"] == start["captureId"] and
                      message["trackingEpoch"] == start["trackingEpoch"], "Unexpected stream frame or identity")
                ordinal += 1
                row = message["data"]
                check(row["ordinal"] == str(ordinal) and row["allPagesVisited"], "Missing or out-of-order round")
                page = row["pages"][0]
                check(page["status"] == "sampled", "Fixture page was not sampled")
                if ordinal == 1:
                    check(page["content"]["origin"] == "baseline", "Missing stream baseline")
                if page["content"]["origin"] == "changed":
                    diff = page["difference"]
                    ranges = [(int(item["base"], 16) - int(seed["address"], 16), int(item["length"]))
                              for item in diff["ranges"]]
                    check(diff["changedBytes"] == 4 and ranges == [(3, 3), (11, 1)], "Stream diff mismatch")
                    changes += 1

            observe(read_record(output))
            send(target, "write")
            check(read_record(target_records)["operation"] == "write", "Fixture write not acknowledged")
            while ordinal < 70:
                observe(read_record(output))
            check(changes == 1 and proc.poll() is None, "Stream did not remain active with one observed change")
            send(proc, "stop")
            terminal = read_record(output)
            while terminal["type"] == "round":
                observe(terminal)
                terminal = read_record(output)
            data = terminal["data"]
            check(terminal["type"] == "summary" and terminal["captureId"] == start["captureId"] and
                  terminal["trackingEpoch"] == start["trackingEpoch"] and data["reason"] == "stop" and
                  data["state"] == "stopped" and data["exitCode"] == 0 and int(data["fullRounds"]) == ordinal and
                  int(data["attemptedRounds"]) == ordinal and int(data["unavailablePages"]) == 0,
                  f"Unexpected stop summary: {terminal}")
            check(output.get(timeout=10) is None and proc.wait(timeout=10) == 0,
                  "Stream did not close cleanly after stop with stdin open")
            print(f"PASS stream: {ordinal} rounds, exact four-byte diff, explicit stop, exit 0")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)


def check_input_receipts(options):
    cases = [
        ("", True, "eof", 0, None, None),
        ("status\n", False, "invalid-command", 1, "invalid-command", None),
        ("stop", True, "input-failed", 1, "unterminated-line", "4"),
        ("x" * ((1 << 20) + 1), False, "input-failed", 1, "line-too-long", str(1 << 20)),
    ]
    for line, close, reason, code, error, offset in cases:
        with open_stream(options) as proc:
            writer = None
            try:
                output = records(proc)
                start = read_record(output)
                check(start["type"] == "start" and start["data"]["state"] == "active", start)
                if error == "line-too-long":
                    def write_oversized_line():
                        try:
                            proc.stdin.write(line)
                            proc.stdin.flush()
                        except BrokenPipeError:
                            # The transport can reject the line before the writer flushes it all.
                            pass

                    writer = threading.Thread(target=write_oversized_line, daemon=True)
                    writer.start()
                else:
                    proc.stdin.write(line)
                    proc.stdin.flush()
                if close:
                    proc.stdin.close()
                data = assert_summary(proc, output, start, reason, "stopped", code)
                issue = data["inputIssue"]
                check(data["issue"] is None, data)
                if error is None:
                    check(issue is None, data)
                else:
                    check(issue["errorId"] == error and issue["byteOffset"] == offset and issue["source"] == "cli" and
                          issue["code"] == code and issue["message"], data)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)
                if writer is not None:
                    writer.join(timeout=5)
                    check(not writer.is_alive(), "Oversized line sender did not close")
    print("PASS stream input receipts: EOF, unknown command, unterminated line, oversized line")


def check_output_loss(options):
    with open_stream(options) as proc:
        try:
            # Keep stdin usable and drop the only stdout reader. The next write must fail.
            proc.stdout.close()
            check(proc.wait(timeout=10) == 3, "Stream did not exit after losing stdout")
            check("memory-stream-output-unavailable" in proc.stderr.read(), "Missing stdout-loss diagnostic")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
    print("PASS stdout loss: distinct stderr diagnostic and exit 3")


def check_output_timeout(options):
    with open_stream(options) as proc:
        try:
            # Keep both parent handles open, without reading any stdout. Transport has a bounded write deadline.
            check(proc.wait(timeout=15) == 3, "Stream did not exit after the stdout write deadline")
            check("memory-stream-output-unavailable" in proc.stderr.read(), "Missing stdout-timeout diagnostic")
            captured = proc.stdout.read()
            check('"type":"start"' in captured and '"type":"summary"' not in captured,
                  "Backpressure test did not receive a start prefix or reported a terminal frame through a blocked pipe")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
    print("PASS stdout backpressure: write deadline and exit 3 with stdin and stdout still open")


def check_partial_then_exit(options, target, target_records):
    with open_stream(options) as proc:
        try:
            output = records(proc)
            start = read_record(output)
            first = read_record(output)
            check(first["type"] == "round" and first["data"]["pages"][0]["status"] == "sampled", first)
            send(target, "protect")
            check(read_record(target_records)["operation"] == "protect", "Fixture protection not acknowledged")
            observed = [first["data"]]
            for _ in range(10):
                frame = read_record(output)
                check(frame["type"] == "round", frame)
                observed.append(frame["data"])
                if frame["data"]["pages"][0]["status"] == "not-readable":
                    break
            else:
                raise RuntimeError("Stream did not observe the inaccessible fixture page")
            send(target, "exit")
            check(target.wait(timeout=10) == 0, "Fixture did not release its buffer and exit cleanly")
            proc.stdin.close()
            data = assert_summary(proc, output, start, "target-exited", "target-exited", 6, observed)
            check(data["issue"]["stage"] == "process-lifetime" and data["inputIssue"] is None, data)
            for ordinal, row in enumerate(observed, 1):
                check(row["ordinal"] == str(ordinal) and int(row["endQpc"]) >= int(row["beginQpc"]), row)
            complete = sum(row["allPagesVisited"] for row in observed)
            pages = [page for row in observed for page in row["pages"]]
            sampled = sum(page["content"] is not None for page in pages)
            check(0 < sampled < len(pages) and int(data["sampledPages"]) == sampled and
                  int(data["unavailablePages"]) == len(pages) - sampled and int(data["fullRounds"]) == complete and
                  int(data["attemptedRounds"]) == len(observed), data)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
    print("PASS target exit: readable prefix and unavailable pages reconciled with terminal counters")


def check_stream_threads(options, target, target_records, seed):
    with open_stream([*options, "--observe-threads"]) as proc:
        try:
            output = records(proc)
            start = read_record(output)
            data = start["data"]
            check(start["type"] == "start" and data["state"] == "active" and data["threadObservationEnabled"]
                  and int(data["observedCreationFileTime"]) == seed["creation"], start)

            ordinal = 0
            previous_observation = None

            def check_round(row):
                nonlocal ordinal, previous_observation
                ordinal += 1
                page, = row["pages"]
                check(int(row["ordinal"]) == ordinal and row["allPagesVisited"] and page["status"] == "sampled"
                      and int(page["returnedBytes"]) == 32, row)
                snapshot = row["threadObservation"]
                check(snapshot is not None and snapshot["snapshotStatus"] == "complete", row)
                check(row["previousThreadObservationRound"] == previous_observation, row)
                previous_observation = row["ordinal"]
                return snapshot

            def read_round():
                frame = read_record(output)
                check(frame["type"] == "round" and frame["captureId"] == start["captureId"] and
                      frame["trackingEpoch"] == start["trackingEpoch"], frame)
                return check_round(frame["data"])

            read_round()
            send(target, "thread-start")
            worker = read_record(target_records)
            check(worker["operation"] == "thread-start", worker)

            def worker_round(status):
                for _ in range(30):
                    for event in read_round()["events"]:
                        if (event["tid"] == worker["tid"] and event["creationTime100ns"] is not None and
                                int(event["creationTime100ns"]) == worker["creation"]):
                            check(event["status"] == status, event)
                            return ordinal
                raise RuntimeError(f"Worker {worker['tid']}:{worker['creation']} not {status} by round {ordinal}")

            observed = worker_round("newly-observed")
            send(target, "thread-end")
            ended = read_record(target_records)
            check(ended["operation"] == "thread-end" and ended["tid"] == worker["tid"], ended)
            exited = worker_round("exited")
            send(proc, "stop")
            trailing = []
            summary = assert_summary(proc, output, start, "stop", "stopped", 0, trailing)
            for row in trailing:
                check_round(row)
            check(summary["threadObservationEnabled"] and int(summary["fullRounds"]) == ordinal, summary)
            check(target.poll() is None, "Stream stop did not leave the owned target alive")
            send(target, "exit")
            check(read_record(target_records)["operation"] == "exit" and target.wait(timeout=10) == 0,
                  "Owned target did not exit cleanly")
            print(f"MEMORY_STREAM_OBSERVE_THREADS=PASS CAPTURE={start['captureId']} EPOCH={start['trackingEpoch']} "
                  f"PID={target.pid} PROCESS_CREATION={seed['creation']} ADDRESS={seed['address']} BYTES=32 "
                  f"WORKER={worker['tid']}:{worker['creation']} OBSERVED_ROUND={observed} EXITED_ROUND={exited} "
                  f"PREVIOUS_ROUND_CHAIN=null,1..{ordinal - 1} "
                  f"FULL_ROUNDS={summary['fullRounds']} STOP_REASON={summary['reason']} CLI_EXIT=0 TARGET_EXIT=0")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)


def validate_evidence_gap(rows, totals, seed, continuous):
    sampled = []
    gaps = []
    unreadable = []
    for ordinal, row in enumerate(rows, 1):
        page, = row["pages"]
        check(row["ordinal"] == (str(ordinal) if continuous else ordinal) and row["allPagesVisited"] and
              int(page["range"]["base"], 16) == int(seed["address"], 16) and int(page["range"]["length"]) == 32, row)
        content = page["content"]
        if content is None:
            check(row["threadObservation"] is None and row["previousThreadObservationRound"] is None and
                  page["previousContent"] is None and page["difference"] is None, row)
            gaps.append(ordinal)
            if page["status"] == "not-readable":
                check(page["mappingBefore"]["protection"] == 0x01 and page["returnedBytes"] is None, row)
                unreadable.append(ordinal)
            continue
        previous = sampled[-1] if sampled else None
        check(page["status"] == "sampled" and int(page["returnedBytes"]) == 32 and
              page["mappingBefore"]["protection"] == 0x04 and content["round"] == row["ordinal"] and
              row["threadObservation"] is not None and row["threadObservation"]["snapshotStatus"] == "complete" and
              row["previousThreadObservationRound"] == previous, row)
        if previous is None:
            check(content["origin"] == "baseline" and page["previousContent"] is None and
                  page["difference"] is None, row)
        sampled.append(row["ordinal"])

    check(unreadable and gaps[0] > 1 and gaps[-1] < len(rows) and gaps == list(range(gaps[0], gaps[-1] + 1)),
          f"Expected one gap containing a PAGE_NOACCESS round between sampled rounds: {gaps}; {unreadable}")
    before = rows[gaps[0] - 2]
    recovered = rows[gaps[-1]]
    page = recovered["pages"][0]
    pre_gap_content = before["pages"][0]["content"]
    check(page["content"]["origin"] == "baseline" and page["previousContent"] is None and
          page["difference"] is None and page["content"]["sha256"] == pre_gap_content["sha256"] and
          int(page["content"]["version"]) == int(pre_gap_content["version"]) + 1 and
          recovered["previousThreadObservationRound"] == before["ordinal"], recovered)
    check(totals["threadObservationEnabled"] and totals["issue"] is None and
          int(totals["sampledPages"]) == len(sampled) and int(totals["unavailablePages"]) == len(gaps) and
          int(totals["fullRounds"]) == int(totals["attemptedRounds"]) == len(rows), totals)
    return (f"PRE_GAP_SNAPSHOT={before['ordinal']} GAP={gaps[0]}..{gaps[-1]} NOACCESS_ROUNDS={len(unreadable)} "
            f"RECOVERY={recovered['ordinal']} RECOVERY_PREVIOUS={recovered['previousThreadObservationRound']} "
            f"RECOVERY_ORIGIN={page['content']['origin']} SAMPLED={len(sampled)} UNAVAILABLE={len(gaps)}")


def check_evidence_gap(options, target, target_records, seed):
    def protection_operation(operation, previous):
        send(target, operation)
        reply = read_record(target_records)
        check(reply["operation"] == operation and reply["previousProtection"] == previous, reply)

    def check_capture(data):
        check(data["pid"] == target.pid and int(data["observedCreationFileTime"]) == seed["creation"] and
              data["threadObservationEnabled"] and data["executionCoverage"] == "not-collected" and
              data["writeAttribution"] == "unknown", data)

    with open_stream(options) as proc:
        try:
            output = records(proc)
            start = read_record(output)
            check(start["type"] == "start" and start["data"]["backend"] == "r3" and
                  start["data"]["state"] == "active", start)
            check_capture(start["data"])
            rows = []

            def until(predicate):
                for _ in range(20):
                    frame = read_record(output)
                    check(frame["type"] == "round" and frame["captureId"] == start["captureId"] and
                          frame["trackingEpoch"] == start["trackingEpoch"], frame)
                    rows.append(frame["data"])
                    page, = frame["data"]["pages"]
                    if predicate(page):
                        return
                raise RuntimeError(f"Stream did not reach the expected page state: {rows[-1]}")

            until(lambda page: page["content"] is not None)
            protection_operation("protect", 0x04)
            until(lambda page: page["status"] == "not-readable")
            protection_operation("restore", 0x01)
            until(lambda page: page["content"] is not None)
            send(proc, "stop")
            summary = assert_summary(proc, output, start, "stop", "stopped", 6, rows)
            check(summary["inputIssue"] is None, summary)
            stream_receipt = validate_evidence_gap(rows, summary, seed, continuous=True)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)

    # Track returns only its final JSON. The existing launcher waits one second before this action.
    def timed_gap():
        protection_operation("protect", 0x04)
        time.sleep(1)
        protection_operation("restore", 0x01)

    result = analyze(["analyze", "memory", "track", *options, "--confirm", "--samples", "32", "--json"],
                     action=timed_gap)
    reply = result["reply"]
    track = reply["data"]
    check(result["exitCode"] == 6 and reply["backend"] == "r3" and reply["status"] == "partial" and
          track["state"] == "completed" and not track["complete"] and len(track["rounds"]) == 32, result)
    check_capture(track)
    track_receipt = validate_evidence_gap(track["rounds"], track, seed, continuous=False)

    check(target.poll() is None, "Memory capture did not leave the owned target alive")
    send(target, "exit")
    check(read_record(target_records)["operation"] == "exit" and target.wait(timeout=10) == 0,
          "Owned target did not exit cleanly")
    print(f"MEMORY_STREAM_EVIDENCE_GAP=PASS CAPTURE={start['captureId']} EPOCH={start['trackingEpoch']} "
          f"{stream_receipt} STOP_REASON={summary['reason']} CLI_EXIT=6")
    print(f"MEMORY_TRACK_EVIDENCE_GAP=PASS CAPTURE={track['captureId']} EPOCH={track['trackingEpoch']} "
          f"{track_receipt} STATE={track['state']} CLI_EXIT=6")
    print(f"OWNED_TARGET PID={target.pid} PROCESS_CREATION={seed['creation']} ADDRESS={seed['address']} BYTES=32 "
          "TARGET_EXIT=0 EXECUTION_COVERAGE=not-collected WRITE_ATTRIBUTION=unknown")


def main(observe_threads=False, evidence_gap=False):
    print(f"CLI {CLI} SHA256 {hashlib.sha256(CLI.read_bytes()).hexdigest()}")
    if not (observe_threads or evidence_gap):
        help_result = subprocess.run([str(CLI), "help", "analyze", "memory", "stream"], capture_output=True,
                                     check=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        check(b"plain stop line" in help_result.stdout and b"--samples" not in help_result.stdout,
               "Built-in continuous command help mismatch")
    fixture = Path(__file__).with_name("memory_watch.py")
    with subprocess.Popen([sys.executable, "-I", "-B", str(fixture), "--target"], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, text=True, encoding="utf-8",
                          creationflags=subprocess.CREATE_NO_WINDOW) as target:
        try:
            target_records = records(target)
            seed = read_record(target_records)
            options = ["--backend", "r3", "--pid", str(target.pid), "--creation-time", str(seed["creation"]),
                       "--address", seed["address"], "--size", "32", "--interval-ms", "125" if evidence_gap else "10"]
            if evidence_gap:
                check_evidence_gap([*options, "--observe-threads"], target, target_records, seed)
                return
            if observe_threads:
                check_stream_threads(options, target, target_records, seed)
                return
            check_finite(options)
            check_stream(options, target, target_records, seed)
            check_input_receipts(options)
            check_output_loss(options)
            check_output_timeout(options)
            check_partial_then_exit(options, target, target_records)
        finally:
            if target.poll() is None:
                target.kill()
                target.wait(timeout=5)


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--observe-threads"], ["--evidence-gap"]):
        raise SystemExit("usage: memory_stream.py [--observe-threads | --evidence-gap]")
    main(observe_threads=sys.argv[1:] == ["--observe-threads"], evidence_gap=sys.argv[1:] == ["--evidence-gap"])
