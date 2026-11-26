"""Compare standalone and capture-owned replay at the same missing terminal checkpoint."""

import argparse
import hashlib
import json
import os
from pathlib import Path
from queue import Queue
import re
import subprocess
import sys
from threading import Thread

from cooperative_api_capture import (AGENT, CLI, COOPERATIVE_ENV, RELEASE, SCRIPT, cleanup_session,
                                     create_project, create_session_directory, invoke)
from project_v1 import owned_project_path, regular_identity


CDB = Path(os.environ['ProgramFiles(x86)']) / 'Windows Kits/10/Debuggers/x64/cdb.exe'
PAUSED = b'AA03_FINAL_READBACK_BREAK'
CLI_PID = re.compile(rb'^\.\s+0\s+id:\s+([\da-f]+)\s+create\s+name:\s+KswordCLI\.exe\s*$', re.M | re.I)


def start_capture(project, target, identity, environment, debugger):
    command = [CLI, 'analyze', 'api-evidence', 'capture', '--project', project, '--title', 'AA-03 final readback',
               '--pid', str(target.pid), '--creation-filetime', str(identity['creation']), '--confirm',
               '--duration-ms', '5000', '--json']
    # CDB owns only the capture CLI. Stop once at the reader entry, which the writer never calls.
    start = ('.reload /f KswordCLI.exe; |; bm /1 KswordCLI!*::ReplayCooperative '
             '"k 4; .echo AA03_FINAL_READBACK_BREAK"; g')
    return subprocess.Popen([debugger, '-G', '-y', RELEASE, '-c', start, *command], env=environment,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            creationflags=subprocess.CREATE_NO_WINDOW)


def collect_transcript(stream, transcript, paused):
    for line in stream:
        transcript.append(line)
        if line.strip() == PAUSED:
            paused.put(b''.join(transcript))
    paused.put(None)


def read_with_marker_absent(project, debuggee, target, identity, transcript):
    paused = Queue()
    reader = Thread(target=collect_transcript, args=(debuggee.stdout, transcript, paused), daemon=True)
    reader.start()
    marker = moved = None
    try:
        at_break = paused.get(timeout=35)
        assert at_break is not None, 'Capture exited before the final replay breakpoint'
        assert b'::ReplayCooperative' in at_break and b'::CaptureResident' in at_break, at_break
        assert CLI_PID.search(at_break), at_break
        assert target.poll() is None, 'Owned target did not survive the capture interval'

        sample_dir, = (project / 'samples').iterdir()
        checkpoints = sample_dir / 'checkpoints'
        markers = sorted(checkpoints.glob('[0-9]*.json'))
        previous_path, marker = markers[-2:]
        previous = json.loads(previous_path.read_bytes())
        final = json.loads(marker.read_bytes())
        ordinal = int(final['generation'])
        sample = sample_dir.name
        assert final['sampleId'] == previous['sampleId'] == sample, (previous, final)
        assert marker.name == f'{ordinal:020d}.json' and previous_path.name == f'{ordinal - 1:020d}.json'
        assert final['finalSegment'] and not previous['finalSegment'] and int(previous['lastSourceSequence']) > 0
        raw = sample_dir / 'raw' / f'{ordinal:020d}.ksaseg'
        marker_identity = regular_identity(marker)
        raw_identity = regular_identity(raw)
        hidden_marker = marker.with_suffix('.unavailable')
        assert not os.path.lexists(hidden_marker), hidden_marker
        marker.rename(hidden_marker)
        moved = hidden_marker

        # The capture CLI is paused and cannot consume the missing marker before this comparison.
        prefix = invoke('analyze', 'api-evidence', 'replay', '--project', project, '--sample', sample,
                        '--limit', '1', accepted=(0,))
        assert (prefix['status'], prefix['committedSegments'], prefix['sourceRows'],
                prefix['failedSegment'], prefix['finalSegment']) == (
                    'readback-prefix', str(ordinal - 1), previous['lastSourceSequence'], None, False), prefix
        assert int(prefix['clueRows']) > 0 and len(prefix['rows']) == 1, prefix
        assert int(prefix['rows'][0]['rawSegment']) < ordinal, prefix
        print(f'STANDALONE_REPLAY_EXIT=0 PREFIX={ordinal - 1} SOURCE_ROWS={prefix["sourceRows"]} '
              f'CLUE_ROWS={prefix["clueRows"]} FAILED_SEGMENT=null', flush=True)

        debuggee.stdin.write(b'g\n')
        debuggee.stdin.flush()
        debuggee.wait(timeout=20)
        reader.join(timeout=3)
        assert not reader.is_alive(), 'Debugger transcript did not close'
        output = b''.join(transcript)
        results = [line[line.index(b'{"schemaVersion"'):] for line in output.splitlines()
                   if b'{"schemaVersion"' in line]
        result, = map(json.loads, results)
        print(f'CLI_CAPTURE_EXIT={debuggee.returncode} ' + json.dumps(result, ensure_ascii=True), flush=True)
        assert debuggee.returncode == 4 and result['command'] == 'analyze api-evidence capture', result
        captured = result['data']
        assert captured['status'] == 'capture-failed' and captured['archiveError'] is None, captured
        assert (captured['sampleId'], captured['pid'], captured['creationFileTime']) == (
            sample, target.pid, str(identity['creation'])), captured
        assert captured['archivedPackets'] == captured['ordinaryPackets'] == final['lastSourceSequence'], captured
        assert all(captured[key] is True for key in ('completedInterval', 'hooksRemoved', 'cleanPipeEof',
                                                      'cleanupComplete')), captured
        assert not captured['targetExited'] and target.poll() is None, captured
        assert captured['archive'] == (prefix | {'failedSegment': str(ordinal)}), captured
        assert regular_identity(raw) == raw_identity and not os.path.lexists(marker), raw
        print(f'CAPTURE_REPLAY_EXIT=4 FAILED_SEGMENT={ordinal} SAME_PREFIX=True', flush=True)
    finally:
        if debuggee.poll() is None:
            try:
                debuggee.stdin.write(b'g\n')
                debuggee.stdin.flush()
            except BrokenPipeError:
                pass
            debuggee.wait(timeout=25)
        debuggee.stdin.close()
        reader.join(timeout=3)
        debuggee.stdout.close()
        if moved is not None:
            moved.rename(marker)
            assert regular_identity(marker) == marker_identity, marker
            print(f'RESTORED_TERMINAL_CHECKPOINT={marker.name}', flush=True)
        if sys.exc_info()[0] is not None:
            print(b''.join(transcript).decode(errors='replace'), flush=True)


def exercise(project, directory, debugger):
    create_project(project, 'AA-03 final readback')
    environment = os.environ | {COOPERATIVE_ENV: str(directory)}
    target = subprocess.Popen([sys.executable, '-B', SCRIPT, '--startup-target'], env=environment,
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              creationflags=subprocess.CREATE_NO_WINDOW)
    identity = debuggee = None
    transcript = []
    try:
        lines = Queue()
        Thread(target=lambda: lines.put(target.stdout.readline()), daemon=True).start()
        identity = json.loads(lines.get(timeout=10))
        assert identity['pid'] == target.pid and identity['creation'] > 0, identity
        debuggee = start_capture(project, target, identity, environment, debugger)
        read_with_marker_absent(project, debuggee, target, identity, transcript)
        tail, errors = target.communicate(timeout=10)
        assert target.returncode == 0, (target.returncode, tail, errors)
        assert json.loads(tail)['agentLoaded'], tail
    finally:
        if target.poll() is None:
            if not target.stdin.closed:
                target.stdin.close()
            target.wait(timeout=10)
        for stream in (target.stdin, target.stdout, target.stderr):
            stream.close()
        print(f'OWNED_TARGET_EXIT={target.returncode}', flush=True)
        if debuggee is not None and debuggee.poll() is not None:
            match = CLI_PID.search(b''.join(transcript))
            if match:
                cleanup_session(directory, target.pid, identity['creation'], int(match.group(1), 16))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cdb', type=Path, default=CDB)
    args = parser.parse_args()
    assert __debug__ and sys.maxsize > 2**32 and os.name == 'nt', 'Run Windows x64 Python with assertions enabled'
    debugger = args.cdb.resolve(strict=True)
    assert (RELEASE / 'KswordCLI.pdb').is_file(), 'Matching Release PDB is required'
    for image in (CLI, AGENT):
        binary = image.read_bytes()
        assert (COOPERATIVE_ENV + '\0').encode('utf-16-le') in binary, image
        print(f'{image.name}_SHA256={hashlib.sha256(binary).hexdigest()}', flush=True)
    with owned_project_path() as project:
        directory = project.parent / 'KswordApiMonCooperative'
        create_session_directory(directory)
        identity = regular_identity(directory)
        exercise(project, directory, debugger)
        assert regular_identity(directory) == identity and not any(directory.iterdir()), directory
        directory.rmdir()
        print('COOPERATIVE_SESSION_DIRECTORY_REMOVED=True', flush=True)
    print('AA03_COOPERATIVE_FINAL_READBACK=PASS', flush=True)


if __name__ == '__main__':
    main()
