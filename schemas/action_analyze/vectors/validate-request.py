"""Validate A0.2 offline contract vectors. All inputs are local static files."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]
BASE_URI = 'https://ksword.invalid/schemas/action_analyze/'
U64_MAX = (1 << 64) - 1
ARCHIVE_LIMIT = 1 << 30
PROFILE_AVAILABILITY = {
    'shell': ('shell',),
    'project-integration': ('shell', 'project-integration'),
    'archive-inspection': ('shell', 'project-integration', 'archive-inspection'),
}


def read(name):
    return json.loads((ROOT / name).read_text(encoding='utf-8'))


def validator(ref, registry):
    return Draft202012Validator({'$ref': BASE_URI + ref}, registry=registry)


def require(actual, expected, case):
    if actual != expected:
        raise SystemExit(f'{case}: expected {expected!r}, got {actual!r}')


def admission(request, methods, envelope, params, limits, profile='shell'):
    if not envelope.is_valid(request):
        return 'invalid-envelope'
    if any(len(request[name].encode('utf-8')) > limits['requestIdBytes']
           for name in ('requestId', 'method')):
        return 'invalid-envelope'

    method = request['method']
    if method not in methods or methods[method]['availability'] not in PROFILE_AVAILABILITY[profile]:
        return 'unsupported-method'

    arguments = request['params']
    if not params[method].is_valid(arguments):
        return 'invalid-params'
    if method == 'controller.hello' and 1 not in arguments['acceptVersions']:
        return 'no-common-version'
    if method == 'sample.list' and any(int(arguments[key]) > U64_MAX
                                       for key in ('generation', 'start') if key in arguments):
        return 'invalid-params'
    if methods[method]['availability'] == 'project-integration' and not fits_project_text(arguments):
        return 'invalid-params'
    if method == 'archive.inspect':
        if int(arguments['ordinal']) > U64_MAX or int(arguments.get('endOffset', '0')) > ARCHIVE_LIMIT:
            return 'invalid-params'
    return 'accept'


def fits_project_text(value):
    if 'title' in value and len(value['title'].encode('utf-8')) > 1024:
        return False
    if 'notes' in value and len(value['notes'].encode('utf-8')) > 65536:
        return False
    return all(fits_project_text(value[key]) for key in ('settings', 'frozenSettings') if key in value)


class WireFault(ValueError):
    pass


def unique_object(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise WireFault('duplicate-key')
    return value


def reject_float(_):
    raise WireFault('floating-point-rejected')


def integer_token(text):
    if len(text) > 20:
        raise WireFault('integer-overflow')
    value = int(text)
    if not -(1 << 63) <= value <= U64_MAX:
        raise WireFault('integer-overflow')
    return value


def check_json_bounds(root, limits):
    pending = [(root, 1)]
    remaining = 65_536
    while pending:
        value, depth = pending.pop()
        if isinstance(value, (dict, list)) and depth > limits['jsonDepth']:
            raise WireFault('depth-limit')
        remaining -= 1
        if remaining < 0:
            raise WireFault('size-limit')
        if isinstance(value, dict):
            if len(value) > limits['objectKeys']:
                raise WireFault('size-limit')
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            if len(value) > limits['arrayItems']:
                raise WireFault('size-limit')
            pending.extend((child, depth + 1) for child in value)


def wire_body(case, base):
    if 'hex' in case:
        return bytes.fromhex(case['hex'])
    if 'raw' in case:
        return case['raw'].encode('utf-8')
    value = dict(base)
    if 'repeatId' in case:
        repeat = case['repeatId']
        value['requestId'] = repeat['text'] * repeat['times'] + repeat.get('suffix', '')
    if 'arrayItems' in case:
        value['params'] = {'items': [0] * case['arrayItems']}
    if 'objectKeys' in case:
        value['params'] = {str(index): index for index in range(case['objectKeys'])}
    if 'nestedArrays' in case:
        # The request and params objects already account for two containers.
        nested = case.get('leaf', 0)
        for _ in range(case['nestedArrays']):
            nested = [nested]
        value['params'] = {'items': nested}
    body = json.dumps(value, ensure_ascii=False).encode('utf-8')
    return body.ljust(case.get('padBytes', 0)) + case['suffix'].encode('utf-8')


def inspect_wire(wire, limits, admit):
    terminated = wire.endswith(b'\n')
    delimiter = 2 if wire.endswith(b'\r\n') else int(terminated)
    body = wire[:-delimiter] if delimiter else wire
    allowed = limits['inputLineBytes']
    if len(body) > allowed and not (not terminated and len(body) == allowed + 1 and body.endswith(b'\r')):
        return 'line-too-long'
    if not terminated:
        return 'unterminated-line'
    if body.startswith(b'\xef\xbb\xbf'):
        return 'bom-rejected'
    try:
        text = body.decode('utf-8')
    except UnicodeDecodeError:
        return 'invalid-utf8'
    if '\r' in text or '\n' in text:
        return 'invalid-json'

    try:
        value = json.loads(text, object_pairs_hook=unique_object, parse_int=integer_token,
                           parse_float=reject_float, parse_constant=reject_float)
        check_json_bounds(value, limits)
        # Round-trip the decoded strings through UTF-8 to reject isolated UTF-16 surrogates.
        json.dumps(value, ensure_ascii=False).encode('utf-8')
    except WireFault as error:
        return str(error)
    except (ValueError, RecursionError):
        return 'invalid-json'
    return admit(value)


def check_capabilities(capability, methods, profile, schema):
    require(schema.is_valid(capability), True, f'{profile} capabilities shape')
    declared = {name: entry['repl'] for name, entry in methods.items()
                if entry['availability'] in PROFILE_AVAILABILITY[profile]}
    advertised = capability['methods']
    require(len(advertised), len(declared), f'{profile} advertised method count')
    require({item['method']: item['repl'] for item in advertised}, declared, f'{profile} advertised methods')


def project_fixtures(vectors):
    project_id = vectors['projectId']
    revision = vectors['revisionId']
    settings = vectors['settings']
    hashes = dict(revisionHash=vectors['hash'], configSemanticHash=vectors['hash'])
    identity = dict(projectId=project_id, generation='5')
    row = dict(sampleId=vectors['sampleId'], snapshotId='40000000-0000-4000-8000-000000000001',
               title='Frozen scope', createdUtc='134000000000000000', revisionId=revision,
               descriptionHash=vectors['hash'], status='not-collected')
    return {
        'project': dict(identity, **hashes, createdUtc=row['createdUtc'], revisionId=revision, settings=settings,
                        sampleCount='2', access='read-write', recoveredPrevious=False, primaryFailure=None),
        'close': dict(projectId=project_id, closed=True),
        'sample': dict(identity, **row, **hashes, frozenSettings=settings),
        'page': dict(identity, start='0', sampleCount='2', nextStart='1', samples=[row]),
    }


def valid_project_result(value, method, validator):
    if not validator.is_valid(value) or not fits_project_text(value):
        return False
    if any(int(value[key]) > U64_MAX for key in ('createdUtc', 'generation', 'sampleCount', 'start', 'nextStart')
           if key in value and value[key] is not None):
        return False
    if 'sampleCount' in value and int(value['sampleCount']) > 4096:
        return False
    if method != 'sample.list':
        return True
    rows = value['samples']
    if any(not fits_project_text(row) or int(row['createdUtc']) > U64_MAX for row in rows):
        return False
    start, count = int(value['start']), int(value['sampleCount'])
    end = start + len(rows)
    if end > count or (end < count and not rows):
        return False
    return value['nextStart'] == (str(end) if end < count else None)


def check_project_vectors(vectors, shell_vectors, registry, methods, admit, messages, results):
    profile = 'project-integration'
    capability = shell_vectors['shellCapabilities']
    capability = dict(capability, projectStorage=True,
                      methods=capability['methods'] + vectors['capabilityMethods'],
                      limits=dict(capability['limits'], replayBytes=33554432))
    check_capabilities(capability, methods, profile, results['controller.capabilities'])

    fields = {key: vectors[key] for key in ('projectId', 'sampleId', 'settings')}
    fields['expectedRevisionId'] = vectors['revisionId']
    for case in vectors['requests']:
        args = case['params'] | {key: fields[key] for key in case.get('include', [])}
        if 'titleRepeat' in case:
            args['title'] = '\U0001f5c2' * case['titleRepeat']
        request = dict(shell_vectors['baseRequest'], method=case['method'], params=args)
        require(admit(request, profile), case['outcome'], case['id'])
        require(admit(request), 'unsupported-method', f"{case['id']} in baseline shell")

    fixtures = project_fixtures(vectors)
    for case in vectors['results']:
        method = case['method']
        value = fixtures[case['base']] | case.get('set', {})
        require(valid_project_result(value, method, results[method]), case['valid'], case['id'])

    # These are receipt fixtures for adapter regression. Static checks verify their wire shape and identities.
    project_error = validator('request-message.schema.json#/$defs/projectError', registry)
    base = dict(shell_vectors['baseMessage'], type='response', requestId='project-1', phase='completed')
    for case in vectors['receipts']:
        method = case['method']
        if 'errorId' in case:
            error = dict(shell_vectors['error'], errorId=case['errorId'], code=case['code'],
                         source=case.get('source', 'cli'), byteOffset=None)
            require(project_error.is_valid(error), True, case['id'])
            receipt = dict(base, error=error, result=None, effectPhase='not-applicable')
        else:
            result = fixtures[case['base']]
            require(valid_project_result(result, method, results[method]), True, case['id'])
            receipt = dict(base, error=None, result=result, effectPhase='observed')
        require(messages.is_valid(receipt), True, case['id'])
        if case.get('replay') == 'same':
            replayed = dict(receipt, streamSequence='9')
            require(messages.is_valid(replayed), True, f"{case['id']} replay")
            if 'laterGeneration' in case:
                require(replayed['result']['generation'], fixtures[case['base']]['generation'], case['id'])
                require(replayed['result']['generation'] != case['laterGeneration'], True, case['id'])
        if case.get('replay') == 'conflict':
            error = dict(shell_vectors['error'], errorId='request-id-conflict', code=1, byteOffset=None)
            rejected = dict(base, streamSequence='9', error=error, result=None, effectPhase='not-applicable')
            require(messages.is_valid(rejected), True, f"{case['id']} conflict")
    return sum(len(vectors[key]) for key in ('requests', 'results', 'receipts'))


def valid_archive_result(value, schema):
    if not schema.is_valid(value):
        return False
    coverage = value['framingCoverage']
    counts = ('requiredRecordCount', 'unsupportedOptionalRecords', 'unsupportedRequiredRecords')
    numbers = [value[key] for key in (*counts, 'generation', 'ordinal', 'createdUtc100ns')]
    numbers.extend(coverage.values())
    if any(int(number) > U64_MAX for number in numbers if number is not None):
        return False

    end = coverage['requestedEndOffset']
    file_size = coverage['fileBytes']
    framed = int(coverage['framedBytes'])
    blocks = int(coverage['blockCount'])
    if end is not None and int(end) > ARCHIVE_LIMIT:
        return False
    if file_size is None:
        if value['framingStatus'] != 'io-error':
            return False
    else:
        limit = min(int(file_size), ARCHIVE_LIMIT if end is None else int(end), ARCHIVE_LIMIT)
        if int(coverage['scanLimitBytes']) != limit or framed > limit:
            return False
        if value['framingStatus'] == 'framing-complete' and (framed != limit or (end and int(end) > int(file_size))):
            return False
    if blocks == 0 and (framed not in (0, 96) or any(int(value[key]) for key in counts)):
        return False
    if blocks > 0 and framed <= 96:
        return False
    if (framed == 0) != (value['createdUtc100ns'] is None):
        return False
    if value['framingStatus'] == 'framing-complete' and framed < 96:
        return False
    if int(value['unsupportedRequiredRecords']) > int(value['requiredRecordCount']):
        return False
    issue = value['framingError']
    return issue is None or int(issue['offset']) <= ARCHIVE_LIMIT


def check_archive_vectors(vectors, project_vectors, shell_vectors, registry, methods, admit, messages, results):
    method = 'archive.inspect'
    profile = 'archive-inspection'
    shell = shell_vectors['shellCapabilities']
    capability = dict(shell, projectStorage=True, archives=True,
                      methods=shell['methods'] + project_vectors['capabilityMethods'] + [vectors['capabilityMethod']],
                      limits=dict(shell['limits'], replayBytes=33554432))
    capabilities_schema = results['controller.capabilities']
    check_capabilities(capability, methods, profile, capabilities_schema)
    require(capabilities_schema.is_valid(dict(capability, archives=False)), False, 'archive flag disagrees with methods')
    require(capabilities_schema.is_valid(dict(capability, methods=capability['methods'][:-1])), False,
            'archive capability missing method')
    base_request = dict(shell_vectors['baseRequest'], method=method)
    for case in vectors['requests']:
        request = dict(base_request, params=vectors['params'] | case['set'])
        require(admit(request, profile), case['outcome'], case['id'])
        for disabled_profile in ('shell', 'project-integration'):
            require(admit(request, disabled_profile), 'unsupported-method', f"{case['id']} in {disabled_profile}")

    base_message = dict(shell_vectors['baseMessage'], type='response', requestId='archive-1', phase='completed',
                        effectPhase='not-applicable')
    for case in vectors['results']:
        base = vectors['result']
        result = base | case['set']
        result['framingCoverage'] = base['framingCoverage'] | case.get('coverage', {})
        response = dict(base_message, result=result, error=None)
        accepted = messages.is_valid(response) and valid_archive_result(result, results[method])
        require(accepted, case['valid'], case['id'])

    errors = validator(methods[method]['errorSchema'], registry)
    for case in vectors['errors']:
        error = dict(shell_vectors['error'], errorId=case['errorId'], source=case['source'], code=case['code'],
                     byteOffset=None)
        response = dict(base_message, result=None, error=error)
        require(messages.is_valid(response) and errors.is_valid(error), case['valid'], case['errorId'])
    return sum(len(vectors[key]) for key in ('requests', 'results', 'errors')) + 3


def main():
    schemas = [read(name) for name in ('value.schema.json', 'request.schema.json', 'request-message.schema.json',
                                       'archive-inspect-method.schema.json', 'live-etw-session.schema.json')]
    for schema in schemas:
        Draft202012Validator.check_schema(schema)
    registry = Registry().with_resources((schema['$id'], Resource.from_contents(schema)) for schema in schemas)
    envelope = validator('request.schema.json', registry)
    messages = validator('request-message.schema.json', registry)
    methods = read('method-catalog.json')['methods']
    params = {name: validator(entry['paramsSchema'], registry) for name, entry in methods.items()}
    results = {name: validator(entry['resultSchema'], registry) for name, entry in methods.items()
               if 'resultSchema' in entry}
    vectors = read('vectors/request-v1.json')
    capability = vectors['shellCapabilities']
    limits = capability['limits']
    check_capabilities(capability, methods, 'shell', results['controller.capabilities'])

    def admit(request, profile='shell'):
        return admission(request, methods, envelope, params, limits, profile)

    base = vectors['baseRequest']
    for case in vectors['requests']:
        request = base | case['set']
        for key in case.get('omit', []):
            del request[key]
        if case.get('projectParams'):
            request['params'] = {'projectId': vectors['projectId']} | request['params']
        require(admit(request, case.get('profile', 'shell')), case['outcome'], case['id'])

    for case in vectors['wire']:
        require(inspect_wire(wire_body(case, base), limits, admit), case['outcome'], case['id'])

    for case in vectors['messages']:
        message = vectors['baseMessage'] | case['set']
        if case.get('capabilities'):
            message['capabilities'] = capability
        if case.get('error'):
            message['error'] = vectors['error']
        valid = messages.is_valid(message)
        if valid:
            valid = all(int(message[key]) <= U64_MAX
                        for key in ('streamSequence', 'inputSequence') if key in message)
        if valid and 'method' in case:
            valid = results[case['method']].is_valid(message['result'])
        require(valid, case['valid'], case['id'])

    total = sum(len(vectors[key]) for key in ('requests', 'wire', 'messages'))
    project_vectors = read('vectors/request-project-v1.json')
    project_total = check_project_vectors(project_vectors, vectors, registry, methods, admit, messages, results)
    archive_total = check_archive_vectors(read('vectors/archive-inspect-method-v1.json'), project_vectors, vectors,
                                          registry, methods, admit, messages, results)
    print(f'Passed {total} A0.2 baseline, {project_total} project, and {archive_total} archive inspection vectors.')


if __name__ == '__main__':
    main()
