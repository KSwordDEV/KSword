"""Exercise the official Release CLI against the existing owned memory fixture."""

import hashlib
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading

from memory_watch import CLI, check, read_record, read_records


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


def main():
    print(f"CLI {CLI} SHA256 {hashlib.sha256(CLI.read_bytes()).hexdigest()}")
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
                       "--address", seed["address"], "--size", "32", "--interval-ms", "10"]
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
    main()
