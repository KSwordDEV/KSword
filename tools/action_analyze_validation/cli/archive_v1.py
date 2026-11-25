"""Exercise archive.inspect on Stored vectors attached to a CLI-created sample."""

from hashlib import sha256
import json
from runpy import run_path
from uuid import UUID

from project_v1 import Client, owned_project_path
from smoke import EXE, SCHEMAS, artifact_sha, contract, invoke, open_pipe, probe_profile, read, require


def vector_material():
    vectors = read('vectors/stored-v1.json')
    fixtures = {}
    for name, spec in vectors['fixtures'].items():
        data = bytes.fromhex(''.join(spec['hex']))
        require((len(data), sha256(data).hexdigest()), (spec['bytes'], spec['sha256']), name)
        fixtures[name] = data
    crc32c = run_path(str(SCHEMAS / 'check_base_v1.py'))['crc32c']
    sample = vectors['crcCheck']
    require(f'{crc32c(bytes.fromhex(sample["inputHex"])):08x}', sample['integerHex'], 'reference CRC-32C')
    return vectors, fixtures, crc32c


def inspect_project(path, validator, methods, caps, vectors, fixtures, crc32c):
    cases = {case['id']: case for case in vectors['cases']}
    created = vectors['expectedCreatedUtc100ns']
    method = 'archive.inspect'

    def fixture(case_name, params, *, identity_matches=True):
        case = cases[case_name]
        data = bytearray(fixtures[case['base']][:case.get('take')])
        if 'append' in case:
            data.extend(fixtures[case['append']])
        data = data[:case.get('truncate')]
        # Rebind only the segment header to the generated project and sample. Preserve block bytes.
        data[24:32] = int(params['ordinal']).to_bytes(8, 'little')
        project_id = params['projectId'] if identity_matches else vectors['expectedIdentity']['projectUUID']
        data[32:48] = UUID(project_id).bytes
        data[48:64] = UUID(params['sampleId']).bytes
        data[92:96] = crc32c(data[:92]).to_bytes(4, 'little')
        return bytes(data), case

    def expectation(params, data, case, *, status='framing-complete', error=None,
                    required=0, optional_unknown=0, required_unknown=0, block=None):
        endpoint = params.get('endOffset')
        return params | {'generation': '2', 'createdUtc100ns': None if status == 'corrupt' else created,
                         'framingStatus': status, 'framingError': error,
                         'framingCoverage': {
                             'requestedEndOffset': endpoint, 'fileBytes': str(len(data)),
                             'scanLimitBytes': str(min(len(data), int(endpoint))) if endpoint else str(len(data)),
                             'framedBytes': str(case['prefixBytes']), 'blockCount': str(case['blocks']),
                             'lastBlockOrdinal': block['ordinal'] if block else None,
                             'lastSequence': block['lastSequence'] if block else None,
                         }, 'requiredRecordCount': str(required),
                         'unsupportedOptionalRecords': str(optional_unknown),
                         'unsupportedRequiredRecords': str(required_unknown),
                         'interpretedBytes': None, 'durableBytes': None}

    with open_pipe(validator, caps, f'archive inspection {ascii(path.name)}') as (exchange, finish, _):
        api = Client(exchange, validator, methods)
        project = api.call('create', 'project.create', {
            'path': str(path), 'settings': {'title': 'Archive fixture', 'notes': ''},
        }, effect=True)
        sample = api.call('register-sample', 'sample.create', {
            'projectId': project['projectId'], 'expectedRevisionId': project['revisionId'],
            'title': 'Registered offline archive sample',
        }, effect=True)
        require((sample['generation'], sample['status']), ('2', 'not-collected'), 'registered sample')
        identity = {'projectId': project['projectId'], 'sampleId': sample['sampleId']}
        params = identity | {'stream': 'raw', 'ordinal': '1'}
        for label, changed in [('ordinal-zero', {'ordinal': '0'}), ('analysis-stream', {'stream': 'analysis'}),
                               ('endpoint-past-limit', {'endOffset': '1073741825'}),
                               ('raw-path-forbidden', {'path': 'unused.ksaseg'})]:
            api.call(label, method, params | changed, error=('invalid-params', 1))

        for label, error_id in [('missing-stream', 'archive-stream-unavailable'),
                                ('missing-segment', 'archive-segment-unavailable')]:
            record = exchange(json.dumps({'schemaVersion': 1, 'requestId': label, 'method': method,
                                          'params': params}).encode('utf-8') + b'\n')
            require((record['type'], record['requestId'], record['effectPhase'], record['result']),
                    ('response', label, 'not-applicable', None), label)
            error = record['error']
            api.errors[method].validate(error)
            require((error['errorId'], error['source'], error['code']), (error_id, 'win32', 2), label)
            if label == 'missing-stream':
                stream_dir = path / 'samples' / sample['sampleId'] / 'raw'
                stream_dir.mkdir(exist_ok=False)

        expected_cases = [
            ('valid-header-alone', {}),
            ('truncated-second-block-payload', {'status': 'truncated', 'required': 1,
                                              'block': vectors['fixtures']['rawSegment']['expectedBlocks'][0]}),
            ('valid-header-alone', {'status': 'corrupt'}),
            ('optional-unknown-record', {'optional_unknown': 1, 'block': {'ordinal': '0', 'lastSequence': '0'}}),
            ('required-unknown-record', {'required': 1, 'required_unknown': 1,
                                         'block': {'ordinal': '0', 'lastSequence': '0'}}),
        ]
        for ordinal, (case_name, options) in enumerate(expected_cases, 1):
            case_params = params | {'ordinal': str(ordinal)}
            mismatch = options.get('status') == 'corrupt'
            data, case = fixture(case_name, case_params, identity_matches=not mismatch)
            if mismatch:
                case = case | {'prefixBytes': 0}
                options = options | {'error': {'reason': 'identity', 'offset': '0', 'win32Error': None}}
            if options.get('status') == 'truncated':
                options = options | {'error': {'reason': 'end-of-file', 'offset': str(len(data)), 'win32Error': None}}
            segment = stream_dir / f'{ordinal:020}.ksaseg'
            with segment.open('xb') as output:
                output.write(data)
            expected = expectation(case_params, data, case, **options)
            response = api.call(f'inspect-{ordinal}', method, case_params)
            require(response, expected, f'inspect {case_name} at ordinal {ordinal}')
            require(segment.read_bytes(), data, 'inspection preserved fixture bytes')

        full_params = params | {'ordinal': '6'}
        full, _ = fixture('raw-segment', full_params)
        with (stream_dir / f'{6:020}.ksaseg').open('xb') as output:
            output.write(full)
        endpoint = full_params | {'endOffset': '96'}
        expected_header = expectation(endpoint, full, cases['valid-header-alone'])
        expected_header.pop('endOffset')
        require(api.call('bounded-header', method, endpoint), expected_header, 'explicit header-only range')
        require(api.call('bounded-header', method, endpoint), expected_header, 'cached bounded inspection')
        api.call('bounded-header', method, full_params, error=('request-id-conflict', 1))

        repl = (f'project open "{path}"\narchive inspect {sample["sampleId"]} raw 6 96\nquit\n')
        stdout, stderr = invoke(('analyze', 'session', '--backend', 'offline'), repl.encode('utf-8'),
                                label=f'archive REPL {ascii(path.name)}')
        require(stderr, b'', 'archive REPL stderr')
        opened, inspected = [json.loads(text) for text in stdout.decode('utf-8').splitlines() if text.startswith('{')]
        require((opened['projectId'], opened['access']), (project['projectId'], 'read-only'), 'REPL project identity')
        require(inspected, expected_header, 'REPL archive inspection matches JSONL')
        api.shutdown(finish)


def main():
    digest = artifact_sha()
    print(f'{EXE} SHA256 {digest}')
    validator, methods = contract()
    profile, caps = probe_profile(read('vectors/request-v1.json')['shellCapabilities'], methods)
    if profile != 'archive-v1':
        print(f'Archive V1 acceptance skipped. The Release artifact advertises {profile}.')
        return 77
    with open_pipe(validator, caps, 'archive capability and schema gate') as (_, finish, _):
        finish('eof')
    require(artifact_sha(), digest, 'artifact before archive tests')
    material = vector_material()
    with owned_project_path() as path:
        for name in ('archive ASCII fixture', '档案 Unicode fixture'):
            inspect_project(path.with_name(name), validator, methods, caps, *material)
    require(artifact_sha(), digest, 'artifact after archive tests')
    print('Release CLI archive V1 acceptance passed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
