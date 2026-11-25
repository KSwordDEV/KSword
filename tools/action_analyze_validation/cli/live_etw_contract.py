"""用正式 R3 CLI 的完整输出核对方法目录及消息 schema。"""

import json

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from live_etw import REPO, run


def check_contract():
    """验证静态请求和现场的完整输出序列。"""
    directory = REPO / 'schemas' / 'action_analyze'

    def read(relative):
        return json.loads((directory / relative).read_text(encoding='utf-8'))

    # 只登记本协议及其依赖，其他草案不一定具有独立的 schema ID。
    documents = [read(name) for name in ('value.schema.json', 'request.schema.json', 'request-message.schema.json',
                                         'archive-inspect-method.schema.json', 'live-etw-session.schema.json',
                                         'live-etw-message.schema.json')]
    registry = Registry().with_resources((doc['$id'], Resource.from_contents(doc)) for doc in documents)

    def validator(ref):
        return Draft202012Validator({'$ref': f'https://ksword.invalid/schemas/action_analyze/{ref}'}, registry=registry)

    catalog = read('live-etw-method-catalog.json')
    base = read(catalog['baseCatalog'])
    method_schemas = {name: validator(entry['resultSchema'])
                      for name, entry in (base['methods'] | catalog['methods']).items()}
    method_schemas.update({name: validator(ref) for name, ref in catalog['resultOverrides'].items()})
    output = validator(catalog['messageSchema'])

    # 独立验证四种方法及非法参数，现场测试核对真实响应。
    requests = read('vectors/live-etw-session-v1.json')
    request_schema = validator('live-etw-session.schema.json')
    for group, expected in (('valid', True), ('invalid', False)):
        for request in requests[group]:
            assert request_schema.is_valid(request) == expected, request

    count = 0
    kinds = set()

    def validate(frame, method=None):
        nonlocal count
        if method:
            method_schemas[method].validate(frame['result'])
            return
        output.validate(frame)
        count += 1
        kinds.add(frame['type'])
        if frame['type'] == 'hello':
            expected_methods = {name: value['repl'] for name, value in (base['methods'] | catalog['methods']).items()}
            advertised = {entry['method']: entry['repl'] for entry in frame['capabilities']['methods']}
            assert advertised == expected_methods, advertised
        if frame['type'] == 'summary' and frame['liveSession']:
            assert frame['archive'] == frame['liveSession']['archive'], frame

    run(validate=validate)
    assert kinds == {'hello', 'response', 'protocolError', 'summary'}, kinds
    print(f'PASS R3 passive ETW contract: {count} live output frames and 10 request vectors')


if __name__ == '__main__':
    check_contract()
