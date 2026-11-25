"""Validate A0.2 offline contract vectors. All inputs are local static files."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]
BASE_URI = 'https://ksword.invalid/schemas/action_analyze/'
U64_MAX = (1 << 64) - 1


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
    if method not in methods or methods[method]['availability'] not in ('shell', profile):
        return 'unsupported-method'

    arguments = request['params']
    if not params[method].is_valid(arguments):
        return 'invalid-params'
    if method == 'controller.hello' and 1 not in arguments['acceptVersions']:
        return 'no-common-version'
    if method == 'sample.list' and any(int(arguments[key]) > U64_MAX
                                       for key in ('generation', 'start') if key in arguments):
        return 'invalid-params'
    return 'accept'


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


def main():
    schemas = [read(name) for name in ('value.schema.json', 'request.schema.json', 'request-message.schema.json')]
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
    require(len(capability['methods']), len(results), 'advertised method count')
    require({entry['method']: entry['repl'] for entry in capability['methods']},
            {name: entry['repl'] for name, entry in methods.items() if entry['availability'] == 'shell'},
            'advertised methods')

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
    print(f'Passed {total} A0.2 request, wire, and output vectors.')


if __name__ == '__main__':
    main()
