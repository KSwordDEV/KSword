"""Run the offline ActionAnalyze smoke against the existing Release CLI on Windows."""

import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
from queue import Queue
from reprlib import repr as short_repr
from runpy import run_path
import subprocess
from threading import Thread

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[3]
EXE = ROOT / 'Ksword5.1/x64/Release/KswordCLI.exe'
SCHEMAS = ROOT / 'schemas/action_analyze'
SESSION = ('analyze', 'session', '--input', 'jsonl', '--output', 'jsonl', '--backend', 'offline')
CAPABILITIES = ('analyze', 'capabilities', '--json', '--backend', 'offline')
METADATA = ('file', 'metadata', 'query', '--path', 'schemas/action_analyze/request.schema.json',
            '--backend', 'r3', '--json')
TIMEOUT = 15
PROFILES = {
    'shell': (False, False, 3, ('shell',)),
    'project-v1': (True, False, 11, ('shell', 'project-integration')),
    'archive-v1': (True, True, 12, ('shell', 'project-integration', 'archive-inspection')),
}


def read(relative):
    return json.loads((SCHEMAS / relative).read_text(encoding='utf-8'))


def require(actual, expected, label):
    if actual != expected:
        raise AssertionError(f'{label}: expected {short_repr(expected)}, got {short_repr(actual)}')


def artifact_sha():
    return hashlib.sha256(EXE.read_bytes()).hexdigest().upper()


def contract():
    schemas = [read(name) for name in ('value.schema.json', 'request.schema.json', 'request-message.schema.json')]
    # Older checkpoints lack the archive schema. The registry stays local to this repository.
    archive_schema = SCHEMAS / 'archive-inspect-method.schema.json'
    resources = schemas + ([read(archive_schema.name)] if archive_schema.is_file() else [])
    registry = Registry().with_resources((schema['$id'], Resource.from_contents(schema)) for schema in resources)
    return Draft202012Validator(schemas[-1], registry=registry), read('method-catalog.json')['methods']


def probe_profile(shell_caps, methods, expected='auto'):
    stdout, stderr = invoke(CAPABILITIES)
    require(stderr, b'', 'offline capabilities stderr')
    result = json.loads(stdout)
    require((result['backend'], result['status']), ('offline', 'success'), 'offline capabilities result')
    caps = result['data']
    profile = next(name for name, (projects, archives, _, _) in PROFILES.items()
                   if caps['projectStorage'] is projects and caps['archives'] is archives)
    if expected != 'auto':
        require(profile, expected, 'advertised profile')
    _, _, count, availability = PROFILES[profile]
    names = {entry['method']: entry['repl'] for entry in caps['methods']}
    require((len(names), len(caps['methods'])), (count, count), f'{profile} exact method count')
    require(names, {name: row['repl'] for name, row in methods.items()
                    if row['availability'] in availability}, f'{profile} method catalog')
    if profile == 'shell':
        require(caps, shell_caps, 'initial shell capabilities')
    else:
        require([entry for entry in caps['methods'] if entry['method'].startswith('controller.')],
                shell_caps['methods'], 'original controller methods')
        require(caps | {'projectStorage': False, 'archives': False, 'methods': shell_caps['methods'],
                        'limits': {k: v for k, v in caps['limits'].items() if k != 'replayBytes'}},
                shell_caps, 'original shell capability values')
        require(caps['limits'].get('replayBytes'), 32 << 20, 'advertised replay byte budget')
    print(f'Advertised acceptance profile = {profile}')
    return profile, caps


def argv(args):
    return [str(EXE), *args]


def invoke(args, payload=b'', code=0, label=''):
    process = subprocess.run(argv(args), cwd=ROOT, input=payload, capture_output=True, timeout=TIMEOUT)
    print(f'{label or "CLI"}: {subprocess.list2cmdline(argv(args))} -> {process.returncode}')
    require(process.returncode, code, f'{label or args} native exit; stderr={process.stderr!r}')
    return process.stdout, process.stderr


def request(request_id, method='controller.capabilities', params=None):
    return {'schemaVersion': 1, 'requestId': request_id, 'method': method,
            'params': {} if params is None else params}


def line(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8') + b'\n'


def decode_frame(frame, validator, caps, ordinal, controller_id=None):
    require(frame.endswith(b'\n'), True, 'stdout frame ends with LF')
    body = frame[:-1]
    require(1 <= len(body) <= caps['limits']['outputFrameBytes'] and b'\r' not in body,
            True, 'UTF-8 JSONL frame length and delimiter')
    record = json.loads(body.decode('utf-8'))
    validator.validate(record)
    require(record['streamSequence'], str(ordinal), 'streamSequence')
    if controller_id is not None:
        require(record['controllerId'], controller_id, 'same controller')
    return record


def read_frames(stdout, validator, caps, reason, code):
    require(stdout.endswith(b'\n'), True, 'stdout ends with LF')
    records = []
    for ordinal, body in enumerate(stdout[:-1].split(b'\n'), 1):
        records.append(decode_frame(body + b'\n', validator, caps, ordinal,
                                    records[0]['controllerId'] if records else None))
    require((records[0]['type'], records[0].get('capabilities')), ('hello', caps), 'greeting')
    summary = records[-1]
    require((summary['type'], summary.get('reason'), summary.get('exitCode')),
            ('summary', reason, code), 'summary')
    return records[1:-1], summary


def check_response(record, request_id, error_id=None, code=None, result=None, effect='not-applicable'):
    require((record['type'], record.get('requestId'), record.get('effectPhase'), record.get('result')),
            ('response', request_id, effect, result), request_id)
    error = record['error']
    require((error['errorId'], error['code']) if error else None,
            (error_id, code) if error_id else None, request_id)


def smoke_commands(caps):
    for args, tokens in [
        (('help',), ('KswordCLI.exe', 'analyze', 'file')),
        (('help', 'analyze'), ('analyze capabilities', 'analyze session')),
        (('help', 'analyze', 'session'), ('--input', '--output', '--backend offline')),
        (('analyze', 'session', '--help'), ('--input', '--output', '--backend offline')),
    ]:
        stdout, stderr = invoke(args)
        require(stderr, b'', args)
        for token in tokens:
            require(token.encode('ascii') in stdout, True, token)

    stdout, stderr = invoke(METADATA)
    require(stderr, b'', METADATA)
    result = json.loads(stdout)
    require((result['status'], result['backend'], result['data']['snapshot']['available'],
             result['data']['snapshot']['win32Error']), ('success', 'r3', True, 0), 'legacy metadata')
    require(Path(result['data']['path']), SCHEMAS / 'request.schema.json', 'metadata path')

    for args, diagnostic in [
        (('analyze', 'session', '--unknown-smoke'), b'unknown option --unknown-smoke'),
        (('analyze', 'session', '--json'), b'unknown option --json'),
        (('analyze', 'session', '--input', 'jsonl', '--output', 'text'), b'supported combinations'),
        (('analyze', 'session', '--backend', 'r3'), b'unsupported backend'),
    ]:
        stdout, stderr = invoke(args, code=1)
        require(stdout, b'', args)
        require(diagnostic in stderr and b'usage:' in stderr, True, args)

    stdout, stderr = invoke((*METADATA, '--unknown-smoke'), code=1)
    require(b'unknown option --unknown-smoke' in stderr, True, 'legacy unknown option')
    require(json.loads(stdout)['status'], 'failed', 'legacy structured parameter error')

    repl = b'\nhelp\nhelp "capabilities"\r\nhelp "unterminated\nhello\ncapabilities\nquit\nhello\n'
    stdout, stderr = invoke(('analyze', 'session'), repl, label='redirected REPL script')
    require(stderr, b'', 'REPL stderr')
    text = stdout.decode('utf-8')
    for expected in ['ActionAnalyze (offline)', 'help [command]', 'capabilities  List',
                     'error: Unterminated quote', 'Offline controller, protocol 1',
                     'Session closed: shutdown']:
        require(expected in text, True, expected)
    require(text.count('Protocol version 1\n'), 1, 'REPL ignores commands after quit')
    require('action> ' in text, False, 'redirected REPL has no console prompt')
    require('project create PATH' in text, caps['projectStorage'], 'REPL project help availability')
    require('archive inspect SAMPLE_ID' in text, caps['archives'], 'REPL archive help availability')


@contextmanager
def open_pipe(validator, caps, label):
    with subprocess.Popen(argv(SESSION), cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as process:
        received = Queue()

        def collect_stdout():
            for chunk in iter(process.stdout.readline, b''):
                received.put(chunk)
            received.put(b'')

        reader = Thread(target=collect_stdout, daemon=True)
        reader.start()
        ordinal = 0
        controller_id = None

        def receive():
            nonlocal ordinal
            chunk = received.get(timeout=TIMEOUT)
            require(bool(chunk), True, f'{label}: unexpected end of stdout')
            ordinal += 1
            return decode_frame(chunk, validator, caps, ordinal, controller_id)

        def exchange(payload):
            process.stdin.write(payload)
            process.stdin.flush()
            return receive()

        def finish(reason='shutdown'):
            if reason == 'eof':
                process.stdin.close()
            summary = receive()
            require((summary['type'], summary['reason'], summary['exitCode']),
                    ('summary', reason, 0), f'{label} summary')
            require(process.wait(timeout=TIMEOUT), 0, f'{label} native exit')
            reader.join(timeout=TIMEOUT)
            require(reader.is_alive(), False, 'stdout closed after shutdown')
            require(received.get(timeout=TIMEOUT), b'', 'EOF follows summary')
            require(received.empty(), True, 'no records after summary')
            require(process.stderr.read(), b'', 'machine session stderr')
            print(f'{label}: {subprocess.list2cmdline(argv(SESSION))} -> {process.returncode}')

        try:
            greeting = receive()
            require((greeting['type'], greeting['capabilities']), ('hello', caps), 'greeting before writing stdin')
            controller_id = greeting['controllerId']
            yield exchange, finish, controller_id
            require(process.returncode, 0, f'{label} must finish explicitly')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=TIMEOUT)
            reader.join(timeout=TIMEOUT)


def smoke_live(validator, caps):
    # Wait for each reply before sending the next request, while keeping stdin open.
    with open_pipe(validator, caps, 'interactive pipe') as (exchange, finish, _):
        hello = request('replay', 'controller.hello', {'acceptVersions': [2, 1]})
        check_response(exchange(line(hello)), 'replay', result={'selectedVersion': 1})
        reversed_keys = dict(reversed(list(hello.items())))
        check_response(exchange(line(reversed_keys).replace(b'\n', b'\r\n')),
                       'replay', result={'selectedVersion': 1})
        changed = request('replay', 'controller.hello', {'acceptVersions': [1, 2]})
        check_response(exchange(line(changed)), 'replay', 'request-id-conflict', 1)
        check_response(exchange(line(request('replay', 'controller.shutdown'))),
                       'replay', 'request-id-conflict', 1)
        check_response(exchange(line(request('retry', 'controller.hello', {'acceptVersions': [2]}))),
                       'retry', 'no-common-version', 5)
        check_response(exchange(line(request('retry'))), 'retry', result=caps)
        check_response(exchange(line(request('close', 'controller.shutdown'))),
                       'close', result={'shutdown': True}, effect='observed')
        finish()


def smoke_vectors(vectors, validator, caps):
    wire_body = run_path(str(SCHEMAS / 'vectors/validate-request.py'))['wire_body']
    cases = []
    detailed_errors = {
        'unsupported-envelope-version': 'unsupported-schema-version',
        'params-required': 'invalid-params',
        'null-params': 'invalid-params',
        'live-envelope': 'unknown-field',
        'control-in-id': 'invalid-request-id',
        'utf8-with-request-id-over-limit': 'invalid-request-id',
    }
    requests = [case for case in vectors['requests'] if case.get('profile', 'shell') == 'shell']
    advertised = {entry['method'] for entry in caps['methods']}
    shell_only = []
    for case in requests:
        value = vectors['baseRequest'] | {'requestId': case['id']} | case['set']
        for field in case.get('omit', []):
            del value[field]
        # Project operations advertised by V1 are covered against an owned path in project_v1.py.
        if case['outcome'] == 'unsupported-method' and value['method'] in advertised:
            shell_only.append(case['id'])
            continue
        if case['id'] == 'same-project-unavailable-in-shell':
            value['params'] = {'path': 'schemas/action_analyze/request.schema.json'}
        cases.append((case, line(value), value['requestId'], value['method']))
    if shell_only:
        print('Shell-only vectors omitted: ' + ', '.join(shell_only))
    shutdown = cases.pop()
    fatal = []
    for case in vectors['wire']:
        value = vectors['baseRequest'] | {'requestId': case['id']}
        payload = wire_body(case, value)
        if case['outcome'] in ('line-too-long', 'unterminated-line'):
            fatal.append((case, payload))
            continue
        if 'repeatId' in case and case['outcome'] == 'accept':
            value = json.loads(payload)
        cases.append((case, payload, value['requestId'], value['method']))

    cases.append(shutdown)
    payload = b''.join(entry[1] for entry in cases) + line(request('after-shutdown'))
    stdout, stderr = invoke(SESSION, payload, label='A0.2 batched requests and wire vectors')
    require(stderr, b'', 'vector stderr')
    records, _ = read_frames(stdout, validator, caps, 'shutdown', 0)
    require(len(records), len(cases), 'one record per input, ignoring trailing data after shutdown')
    for ordinal, (record, (case, _, request_id, method)) in enumerate(zip(records, cases), 1):
        outcome = detailed_errors.get(case['id'], case['outcome'])
        if outcome == 'accept':
            result = {'controller.hello': {'selectedVersion': 1}, 'controller.capabilities': caps,
                      'controller.shutdown': {'shutdown': True}}[method]
            check_response(record, request_id, result=result,
                           effect='observed' if method == 'controller.shutdown' else 'not-applicable')
        elif case['id'] in {
            'control-in-id', 'utf8-with-request-id-over-limit', 'array-item-cap',
            '33-containers-with-scalar-leaf', 'duplicate-decoded-key', 'json-fraction',
            'leading-zero-number', 'json-integer-overflow', 'stray-cr', 'bad-utf8',
            'bom', 'lone-surrogate',
        }:
            require(record['type'], 'protocolError', case['id'])
            require((record['requestId'], record['inputSequence'], record['error']['errorId'],
                     record['error']['code']), (None, str(ordinal), outcome, 1), case['id'])
        else:
            code = 5 if outcome in ('unsupported-method', 'no-common-version') else 1
            check_response(record, request_id, outcome, code)

    for case, payload in fatal:
        stdout, stderr = invoke(SESSION, payload, code=1, label=case['id'])
        require(stderr, b'', case['id'])
        records, summary = read_frames(stdout, validator, caps, 'protocol-failed', 1)
        error, = records
        require((error['type'], error['requestId'], error['inputSequence'], error['error']['errorId'],
                 error['error']['code']), ('protocolError', None, '1', case['outcome'], 1), case['id'])
        require(summary['error'], error['error'], case['id'])

    stdout, stderr = invoke(SESSION, label='clean EOF')
    require(stderr, b'', 'EOF stderr')
    records, _ = read_frames(stdout, validator, caps, 'eof', 0)
    require(records, [], 'empty input produces greeting and summary only')
    print(f'Native vector inputs checked: {len(requests) - len(shell_only)} request, {len(vectors["wire"])} wire')


def smoke_ledger(validator, caps):
    limit = caps['limits']['replayEntries'] - int(caps['projectStorage'])
    method = 'controller.hello'
    params = {'acceptVersions': [1]}
    payload = b''.join(line(request(f'ledger-{i}', method, params)) for i in range(limit))
    payload += line(request('ledger-full', method, params))
    payload += line(request('ledger-0', method, params))
    payload += line(request('ledger-close', 'controller.shutdown'))
    stdout, stderr = invoke(SESSION, payload, label='full replay ledger')
    require(stderr, b'', 'replay ledger stderr')
    records, _ = read_frames(stdout, validator, caps, 'shutdown', 0)
    require(len(records), limit + 3, 'replay ledger response count')
    for index, record in enumerate(records[:limit]):
        check_response(record, f'ledger-{index}', result={'selectedVersion': 1})
    check_response(records[limit], 'ledger-full', 'request-ledger-full', 6)
    check_response(records[limit + 1], 'ledger-0', result={'selectedVersion': 1})
    check_response(records[limit + 2], 'ledger-close', result={'shutdown': True}, effect='observed')
    print(f'Entry limit reached after {limit} ordinary replies. Cached replay and fresh shutdown passed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', default='auto', choices=('auto', *PROFILES))
    options = parser.parse_args()
    digest = artifact_sha()
    print(f'{EXE} SHA256 {digest}')
    vectors = read('vectors/request-v1.json')
    validator, methods = contract()
    _, caps = probe_profile(vectors['shellCapabilities'], methods, options.profile)
    smoke_commands(caps)
    smoke_live(validator, caps)
    smoke_vectors(vectors, validator, caps)
    smoke_ledger(validator, caps)
    require(artifact_sha(), digest, 'artifact during smoke')
    print('Release CLI offline smoke passed.')


if __name__ == '__main__':
    main()
