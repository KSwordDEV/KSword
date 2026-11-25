"""Accept the offline project adapter using one owned project in the fixed Release directory."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
from shutil import rmtree
from stat import FILE_ATTRIBUTE_REPARSE_POINT
import subprocess

from smoke import (EXE, ROOT, TIMEOUT, artifact_sha, contract, invoke, line, open_pipe,
                   probe_profile, read, request, require)


SCRATCH = EXE.parent / 'action-analyze-cli-validation'
SCHEMA_BASE = 'https://ksword.invalid/schemas/action_analyze/'
REVISION_ONE = {'title': 'Revision one', 'notes': 'Frozen notes\n\t第一份'}
# A full-size settings result lets the byte budget bind well before the entry count.
REVISION_TWO = {'title': 'Revision two', 'notes': 'B' * 65536}


def regular_identity(path):
    info = path.lstat()
    require(bool(info.st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT), False, f'reparse point {path}')
    return info.st_dev, info.st_ino


def check_scratch_location():
    for path in reversed(SCRATCH.parents):
        if path.is_relative_to(ROOT):
            regular_identity(path)
    require(SCRATCH.parent.resolve(strict=True), SCRATCH.parent, 'absolute scratch parent')
    check = subprocess.run(['git', 'ls-files', '-z', '--', SCRATCH.relative_to(ROOT).as_posix()],
                           cwd=ROOT, capture_output=True, check=True, timeout=TIMEOUT)
    require(check.stdout, b'', 'scratch location contains no tracked files')


@contextmanager
def owned_project_path():
    check_scratch_location()
    # Atomic ownership claim. Existing fixtures belong to another run or developer.
    SCRATCH.mkdir(exist_ok=False)
    identity = regular_identity(SCRATCH)
    try:
        yield SCRATCH / 'offline project fixture'
    finally:
        check_scratch_location()
        require(SCRATCH.resolve(strict=True), SCRATCH, 'absolute owned scratch')
        require(regular_identity(SCRATCH), identity, 'same owned scratch directory')
        for parent, directories, files in os.walk(SCRATCH, followlinks=False, onerror=raise_walk_error):
            for name in directories + files:
                regular_identity(Path(parent) / name)
        rmtree(SCRATCH)
        require(os.path.lexists(SCRATCH), False, 'owned scratch removed')
        print(f'Cleaned {SCRATCH}')


def raise_walk_error(error):
    raise error


class Client:
    def __init__(self, exchange, validator, methods):
        self.exchange = exchange
        self.results = {name: validator.evolve(schema={'$ref': SCHEMA_BASE + entry['resultSchema']})
                        for name, entry in methods.items() if 'resultSchema' in entry}

    def call(self, request_id, method, params=None, *, effect=False, error=None):
        record = self.exchange(line(request(request_id, method, params)))
        require((record['type'], record.get('requestId'), record.get('effectPhase')),
                ('response', request_id, 'observed' if effect else 'not-applicable'), request_id)
        if record['error']:
            actual = (record['error']['errorId'], record['error']['code'])
        else:
            actual = None
        require(actual, error, request_id)
        result = record['result']
        if not error:
            self.results[method].validate(result)
        return result

    def shutdown(self, finish):
        require(self.call('shutdown', 'controller.shutdown', effect=True), {'shutdown': True}, 'shutdown effect')
        finish()


def frozen_sample(sample, revision, generation, title):
    require((sample['projectId'], sample['generation'], sample['title'], sample['status']),
            (revision['projectId'], generation, title, 'not-collected'), 'sample identity')
    require(sample['frozenSettings'], revision['settings'], 'frozen settings')
    for key in ('revisionId', 'revisionHash', 'configSemanticHash'):
        require(sample[key], revision[key], f'frozen {key}')


def check_page(page, project, generation, start, count, next_start, samples):
    require((page['projectId'], page['generation'], page['start'], page['sampleCount'], page['nextStart']),
            (project['projectId'], generation, start, count, next_start), 'page identity and continuation')
    keys = ('sampleId', 'title', 'createdUtc', 'revisionId', 'snapshotId', 'descriptionHash', 'status')
    require(page['samples'], [{key: sample[key] for key in keys} for sample in samples], 'page rows')


def check_repl_isolation(path, project, first):
    # The writer stays open while a separate REPL starts with no project selected.
    script = (f'project status\nproject open "{path}"\nproject status\n'
              f'sample status {first["sampleId"]}\nproject close\nquit\n')
    stdout, stderr = invoke(('analyze', 'session', '--backend', 'offline'), script.encode('utf-8'),
                            label='separate read-only REPL')
    require(stderr, b'', 'project REPL stderr')
    lines = stdout.decode('utf-8').splitlines()
    require(lines[1], 'error: No project is open', 'REPL starts without JSONL project state')
    opened, queried, sample, closed = [json.loads(text) for text in lines if text.startswith('{')]
    require(queried, opened, 'REPL query')
    require((opened['projectId'], opened['access'], opened['generation']),
            (project['projectId'], 'read-only', project['generation']), 'explicit REPL open')
    require(sample, first | {'generation': project['generation']}, 'REPL reads same stored sample')
    require(closed, {'projectId': project['projectId'], 'closed': True}, 'REPL close')


def exercise_lifecycle(path, validator, methods, caps):
    with open_pipe(validator, caps, 'same-process project lifecycle') as (exchange, finish, controller_id):
        api = Client(exchange, validator, methods)
        for method in ('session.open', 'control.pause', 'archive.query', 'rule.prepare', 'request.cancel'):
            api.call(f'closed-{method}', method, error=('unsupported-method', 5))

        create = {'path': str(path), 'settings': REVISION_ONE}
        initial = api.call('create', 'project.create', create, effect=True)
        require((initial['settings'], initial['access'], initial['generation'], initial['sampleCount']),
                (REVISION_ONE, 'read-write', '1', '0'), 'first project revision')
        identity = {'projectId': initial['projectId']}
        wrong_project = {'projectId': '10000000-0000-4000-8000-000000000001'}
        api.call('wrong-project', 'project.query', wrong_project, error=('project-id-mismatch', 1))
        revision_one = identity | {'expectedRevisionId': initial['revisionId']}
        first_params = revision_one | {'title': 'Sample one'}
        first = api.call('sample-1', 'sample.create', first_params, effect=True)
        frozen_sample(first, initial, '2', 'Sample one')
        require(api.call('sample-1', 'sample.create', dict(reversed(list(first_params.items()))), effect=True),
                first, 'exact sample replay with reordered parameters')
        api.call('sample-1', 'sample.create', first_params | {'title': 'changed retry'},
                 error=('request-id-conflict', 1))

        save_params = revision_one | {'settings': REVISION_TWO}
        saved = api.call('save-r2', 'project.save', save_params, effect=True)
        require((saved['projectId'], saved['settings'], saved['generation'], saved['sampleCount']),
                (initial['projectId'], REVISION_TWO, '3', '1'), 'second project revision')
        require(saved['revisionId'] != initial['revisionId'], True, 'distinct revisions')
        require(api.call('save-r2', 'project.save', save_params, effect=True), saved, 'save replay is immutable')
        revision_two = identity | {'expectedRevisionId': saved['revisionId']}
        api.call('stale-save', 'project.save', revision_one | {'settings': REVISION_ONE}, error=('stale-revision', 1))
        api.call('stale-sample', 'sample.create', first_params, error=('stale-revision', 1))
        api.call('stale-sample', 'sample.create', first_params, error=('stale-revision', 1))
        api.call('stale-sample', 'sample.create', revision_two | {'title': 'changed stale request'},
                 error=('request-id-conflict', 1))
        require(api.call('query-before-second', 'project.query', identity), saved, 'stale requests leave state intact')

        old_page_params = identity | {'generation': saved['generation'], 'limit': 1}
        old_page = api.call('old-page', 'sample.list', old_page_params)
        check_page(old_page, initial, '3', '0', '1', None, [first])
        second = api.call('sample-2', 'sample.create', revision_two | {'title': 'Sample two'}, effect=True)
        frozen_sample(second, saved, '4', 'Sample two')
        for field in ('sampleId', 'snapshotId'):
            require(first[field] != second[field], True, f'distinct {field}')
        require(api.call('old-page', 'sample.list', old_page_params), old_page, 'historical page replay')
        api.call('stale-page', 'sample.list', old_page_params | {'start': '0'}, error=('stale-generation', 1))
        api.call('no-generation', 'sample.list', identity | {'start': '1'}, error=('invalid-params', 1))
        page_one = api.call('page-one', 'sample.list', identity | {'limit': 1})
        check_page(page_one, initial, '4', '0', '2', '1', [first])
        page_two = api.call('page-two', 'sample.list', identity | {'generation': page_one['generation'],
                            'start': page_one['nextStart'], 'limit': 1})
        check_page(page_two, initial, '4', '1', '2', None, [second])
        for index, sample in enumerate((first, second), 1):
            value = api.call(f'query-sample-{index}', 'sample.query', identity | {'sampleId': sample['sampleId']})
            require(value, sample | {'generation': '4'}, f'sample {index} keeps its frozen revision')

        closed = {'projectId': initial['projectId'], 'closed': True}
        require(api.call('close-project', 'project.close', identity, effect=True), closed, 'close writer')
        api.call('query-closed', 'project.query', identity, error=('project-not-open', 1))
        require(api.call('create', 'project.create', create, effect=True), initial, 'replay create after close')
        api.call('query-still-closed', 'project.query', identity, error=('project-not-open', 1))
        reopened = api.call('reopen', 'project.open', {'path': str(path / 'project.ksaproj')}, effect=True)
        require(reopened, saved | {'generation': '4', 'sampleCount': '2', 'access': 'read-only'}, 'read-only reopen')
        require(api.call('close-project', 'project.close', identity, effect=True), closed, 'replay old close')
        require(api.call('query-reopened', 'project.query', identity), reopened, 'old close leaves reopened project open')
        api.call('save-readonly', 'project.save', revision_two | {'settings': REVISION_ONE}, error=('project-read-only', 1))
        api.call('sample-readonly', 'sample.create', revision_two | {'title': 'No third sample'}, error=('project-read-only', 1))
        for index, sample in enumerate((first, second), 1):
            value = api.call(f'reopened-sample-{index}', 'sample.query', identity | {'sampleId': sample['sampleId']})
            require(value, sample | {'generation': '4'}, f'reopened sample {index}')
        require(api.call('close-reader', 'project.close', identity, effect=True), closed, 'close reader')
        writer = api.call('restore-writer', 'project.open', {'path': str(path), 'access': 'read-write'}, effect=True)
        require(writer, reopened | {'access': 'read-write'}, 'explicit writer reopen releases old lock')
        check_repl_isolation(path, writer, first)
        require(api.call('writer-after-repl', 'project.query', identity), writer, 'REPL leaves JSONL writer intact')
        # Keep the writer open and exercise orderly EOF cleanup before the next controller opens it.
        finish('eof')
    return writer, controller_id


def exercise_byte_budget(path, project, previous_controller, validator, methods, caps):
    with open_pipe(validator, caps, 'V1 replay byte budget') as (exchange, finish, controller_id):
        require(controller_id != previous_controller, True, 'fresh controller identity')
        api = Client(exchange, validator, methods)
        identity = {'projectId': project['projectId']}
        # The former create ID is reusable in this controller, and no project was inherited.
        api.call('create', 'project.query', identity, error=('project-not-open', 1))
        opened = api.call('open', 'project.open', {'path': str(path), 'access': 'read-write'}, effect=True)
        require(opened, project, 'EOF released the previous writer')

        byte_limit = caps['limits']['replayBytes']
        notes_bytes = len(REVISION_TWO['notes'].encode('utf-8'))
        upper_bound = byte_limit // notes_bytes
        # Each successful query retains a full settings result with these notes.
        for index in range(upper_bound + 1):
            query_id = f'heavy-query-{index}'
            record = exchange(line(request(query_id, 'project.query', identity)))
            require(record['requestId'], query_id, 'ledger response correlation')
            if record['error']:
                require((record['error']['errorId'], record['error']['code']),
                        ('request-ledger-full', 6), 'replay byte limit failure')
                break
            require(record['result'], opened, query_id)
        else:
            raise AssertionError('Replay ledger admitted settings beyond the advertised byte budget')
        require(upper_bound * 3 // 4 <= index < min(caps['limits']['replayEntries'], upper_bound + 1),
                True, 'byte limit bound with large settings')
        print(f'Byte limit reached after {index} large project replies')
        require(api.call('heavy-query-0', 'project.query', identity), opened, 'cache survives byte limit')
        api.call('blocked-write', 'project.save', identity | {'expectedRevisionId': project['revisionId'],
                 'settings': {'title': 'Rejected write', 'notes': ''}}, error=('request-ledger-full', 6))
        closed = api.call('close-reserved', 'project.close', identity, effect=True)
        require(closed, identity | {'closed': True}, 'reserved close survives byte limit')
        require(api.call('close-reserved', 'project.close', identity, effect=True), closed, 'reserved close replay')
        api.shutdown(finish)

    with open_pipe(validator, caps, 'post-limit read-only reopen') as (exchange, finish, _):
        api = Client(exchange, validator, methods)
        reopened = api.call('open', 'project.open', {'path': str(path)}, effect=True)
        require(reopened, project | {'access': 'read-only'}, 'ledger-full write made no persistent change')
        api.shutdown(finish)


def main():
    digest = artifact_sha()
    print(f'{EXE} SHA256 {digest}')
    validator, methods = contract()
    profile, caps = probe_profile(read('vectors/request-v1.json')['shellCapabilities'], methods)
    if profile != 'project-v1':
        print('V1 acceptance skipped. The Release artifact advertises the shell profile.')
        return 77

    # Validate the live greeting before reserving the fixed project directory.
    with open_pipe(validator, caps, 'V1 capability and schema gate') as (_, finish, _):
        finish('eof')
    require(artifact_sha(), digest, 'artifact before project tests')
    with owned_project_path() as path:
        project, controller_id = exercise_lifecycle(path, validator, methods, caps)
        exercise_byte_budget(path, project, controller_id, validator, methods, caps)
    require(artifact_sha(), digest, 'artifact after project tests')
    print('Release CLI offline project V1 acceptance passed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
