import json

from . import __version__
from .rules import RULES


def text(findings, path):
    if not findings:
        return '%s: no problems found' % path
    out = []
    for f in findings:
        out.append('%s  %-7s %s  %s\n         %s' % (f.rule, f.severity, path, f.where, f.message))
    counts = {s: sum(f.severity == s for f in findings) for s in ('error', 'warning', 'note')}
    out.append('\n%d error(s), %d warning(s), %d note(s)' % (counts['error'], counts['warning'], counts['note']))
    return '\n'.join(out)


def as_json(findings, path):
    return json.dumps([dict(f.__dict__, file=path) for f in findings], indent=2, ensure_ascii=False)


def sarif(per_file):
    """SARIF 2.1.0, so results show up in GitHub code scanning next to the flow file.
    per_file is a list of (findings, path); all files go into one run."""
    rules = [{'id': rid, 'name': title.replace(' ', '_'), 'shortDescription': {'text': title},
              'defaultConfiguration': {'level': sev}}
             for rid, (sev, title, _) in sorted(RULES.items())]
    results = [{
        'ruleId': f.rule,
        'level': f.severity,
        'message': {'text': '%s: %s' % (f.where, f.message)},
        'locations': [{
            'physicalLocation': {'artifactLocation': {'uri': path.replace('\\', '/')}},
            'logicalLocations': [{'fullyQualifiedName': f.where, 'name': f.component_id}],
        }],
        'partialFingerprints': {'componentId': f.component_id + '/' + f.rule},
    } for findings, path in per_file for f in findings]
    return json.dumps({
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'version': '2.1.0',
        'runs': [{'tool': {'driver': {'name': 'nifilint', 'version': __version__, 'rules': rules}},
                  'results': results}],
    }, indent=2, ensure_ascii=False)
