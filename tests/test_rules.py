import json
import pathlib

import pytest

from nifilint import flow, rules
from nifilint.__main__ import main

FIXTURES = pathlib.Path(__file__).parent / 'fixtures'


@pytest.fixture
def findings():
    return rules.run(flow.load(FIXTURES / 'orders_flow.json'))


def ids(findings, rule):
    return sorted(f.component_id for f in findings if f.rule == rule)


def test_failure_auto_terminated(findings):
    assert ids(findings, 'NFL001') == ['p-convert', 'p-post']
    post = next(f for f in findings if f.rule == 'NFL001' and f.component_id == 'p-post')
    assert 'Failure' in post.message and 'No Retry' in post.message


def test_plaintext_secret_but_not_parameters(findings):
    hits = [f for f in findings if f.rule == 'NFL002']
    assert [f.component_id for f in hits] == ['p-list']
    assert '"Password"' in hits[0].message
    assert 'Winter2026' not in hits[0].message          # never repeat the secret in the report


def test_unbounded_queue(findings):
    hits = [f for f in findings if f.rule == 'NFL003']
    assert [f.component_id for f in hits] == ['c-2']
    assert '"success" (ConvertRecord -> Send to ERP)' in hits[0].message


def test_busy_source_only_for_processors_without_input(findings):
    assert ids(findings, 'NFL004') == ['p-list']


def test_hardcoded_urls(findings):
    assert ids(findings, 'NFL005') == ['p-list', 'p-post']


def test_default_name_unreachable_disabled(findings):
    assert ids(findings, 'NFL006') == ['p-convert']
    assert ids(findings, 'NFL007') == ['p-old']
    assert ids(findings, 'NFL008') == ['p-old']


def test_dangling_connection(findings):
    assert ids(findings, 'NFL011') == ['c-3']


def test_errors_sort_first(findings):
    order = [f.severity for f in findings]
    assert order == sorted(order, key=['error', 'warning', 'note'].index)


def test_reads_flow_json_gz_format(tmp_path):
    import gzip
    data = {'rootGroup': {'identifier': 'r', 'name': 'NiFi Flow', 'processGroups': [
        {'identifier': 'g', 'name': 'Inner', 'processors': [
            {'identifier': 'x', 'name': 'LogAttribute', 'type': 'org.apache.nifi.processors.standard.LogAttribute',
             'autoTerminatedRelationships': ['success']}]}]}}
    path = tmp_path / 'flow.json.gz'
    with gzip.open(path, 'wt') as f:
        json.dump(data, f)
    found = rules.run(flow.load(path))
    assert {f.rule for f in found} == {'NFL006', 'NFL007'}
    assert found[0].where.startswith('NiFi Flow / Inner')


def test_deep_nesting_and_long_scripts():
    group = {'identifier': 'g5', 'name': 'L5', 'processors': [
        {'identifier': 's', 'name': 'Score audits', 'type': 'org.apache.nifi.processors.script.ExecuteScript',
         'schedulingPeriod': '1 min', 'properties': {'Script Body': '\n'.join('x = %d' % i for i in range(80))}}]}
    for level in range(4, 0, -1):
        group = {'identifier': 'g%d' % level, 'name': 'L%d' % level, 'processGroups': [group]}
    found = rules.run(flow.parse({'flowContents': {'identifier': 'root', 'name': 'Root', 'processGroups': [group]}}))
    assert any(f.rule == 'NFL009' and '80 lines' in f.message for f in found)
    assert any(f.rule == 'NFL010' for f in found)


def test_cli_exit_codes_and_disable(capsys):
    path = str(FIXTURES / 'orders_flow.json')
    assert main([path]) == 1
    assert main([path, '--disable', 'NFL001,NFL002,NFL011']) == 0
    assert main([path, '--disable', 'NFL001,NFL002,NFL011', '--fail-on', 'warning']) == 1


def test_sarif_output(capsys):
    main([str(FIXTURES / 'orders_flow.json'), '--format', 'sarif'])
    doc = json.loads(capsys.readouterr().out)
    run = doc['runs'][0]
    assert doc['version'] == '2.1.0'
    assert {r['id'] for r in run['tool']['driver']['rules']} >= {'NFL001', 'NFL011'}
    assert all(r['locations'][0]['physicalLocation']['artifactLocation']['uri'].endswith('orders_flow.json')
               for r in run['results'])


def test_not_a_flow(tmp_path):
    bad = tmp_path / 'x.json'
    bad.write_text('{"hello": 1}')
    assert main([str(bad)]) == 2
