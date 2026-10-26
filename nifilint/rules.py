"""The checks. Each rule is a function that takes a Flow and yields Findings.

Every rule here comes from something that has gone wrong in a real flow: errors dropped on the floor, a
password sitting in a plain property, a queue that filled up the disk, a ListFile hammering a share every
millisecond.
"""
import re
from dataclasses import dataclass

ERROR, WARNING, NOTE = 'error', 'warning', 'note'


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    where: str
    component_id: str


RULES = {}


def rule(rule_id, severity, title):
    def register(fn):
        RULES[rule_id] = (severity, title, fn)
        return fn
    return register


# Processors that start a flow, so having no incoming connection is expected
SOURCE_HINTS = ('Generate', 'List', 'Get', 'Consume', 'Listen', 'Query', 'Fetch', 'Tail', 'Capture',
                'Invoke', 'Execute', 'Handle', 'Scan')
SECRET_NAME = re.compile(r'password|passphrase|secret|token|api[ ._-]?key|credential|private[ ._-]?key', re.I)
# Settings *about* a secret, not the secret itself: "Authorization Mode", "Token Type", "Password Required"
SECRET_SETTING = re.compile(r'(mode|type|strategy|required|enabled|use|provider|location|header name)', re.I)
NOT_A_SECRET = {'true', 'false', 'none', 'basic', 'bearer'}
HARDCODED = re.compile(r'^(https?://|jdbc:|sftp://|ftp://|[a-zA-Z]:\\|/(home|data|opt|mnt|srv)/)')
REFERENCE = re.compile(r'#\{[^}]+\}|\$\{[^}]+\}')


def _props(p):
    return p.raw.get('properties') or {}


def _auto_terminated(p):
    return set(p.raw.get('autoTerminatedRelationships') or [])


@rule('NFL001', ERROR, 'failure relationship is auto-terminated')
def failure_auto_terminated(flow):
    for p in flow.processors():
        # Names vary in case between processors (InvokeHTTP in NiFi 2 uses "Failure", "No Retry", "Retry")
        dropped = {r for r in _auto_terminated(p) if r.lower() in ('failure', 'comms.failure', 'no retry', 'retry')}
        if dropped:
            yield Finding('NFL001', ERROR,
                          '%s relationship%s auto-terminated: failed FlowFiles are silently deleted. Route them '
                          'somewhere visible (a funnel, a dead-letter queue or an alert).'
                          % (', '.join(sorted(dropped)), ' is' if len(dropped) == 1 else 's are'),
                          p.where, p.id)


@rule('NFL002', ERROR, 'plaintext secret in a non-sensitive property')
def plaintext_secret(flow):
    for p in flow.processors():
        for name, value in _props(p).items():
            if not value or not SECRET_NAME.search(name) or SECRET_SETTING.search(name):
                continue
            if REFERENCE.search(str(value)) or str(value).strip().lower() in NOT_A_SECRET:
                continue
            # Flow definitions strip real sensitive properties, so a value here was stored in plain text
            yield Finding('NFL002', ERROR,
                          'property "%s" holds a literal value that looks like a secret. Use a sensitive '
                          'parameter (#{...}) so it is encrypted and not exported.' % name, p.where, p.id)


@rule('NFL003', WARNING, 'unbounded or oversized queue')
def back_pressure(flow):
    for c in flow.connections():
        count = int(c.raw.get('backPressureObjectThreshold') or 0)
        size = str(c.raw.get('backPressureDataSizeThreshold') or '').strip()
        label = _connection_label(flow, c)
        if count == 0 or size in ('', '0 B', '0 KB', '0 MB', '0 GB'):
            yield Finding('NFL003', WARNING,
                          'back pressure is switched off on %s. If the next step stops, this queue grows until '
                          'the content repository fills the disk.' % label, c.group_path, c.id)
        elif count > 1_000_000:
            yield Finding('NFL003', WARNING, 'back pressure on %s is %s FlowFiles, which is too high to protect '
                          'the node.' % (label, format(count, ',')), c.group_path, c.id)


@rule('NFL004', WARNING, 'source processor runs continuously')
def busy_source(flow):
    for p in flow.processors():
        incoming = any(_dest_id(c) == p.id for c in flow.connections())
        if incoming or p.raw.get('schedulingStrategy', 'TIMER_DRIVEN') != 'TIMER_DRIVEN':
            continue
        period = str(p.raw.get('schedulingPeriod', '0 sec')).strip()
        if re.fullmatch(r'0+\s*(ms|millis|sec|secs|seconds?|min)?', period) and p.short_type.startswith(SOURCE_HINTS):
            yield Finding('NFL004', WARNING,
                          '%s has no incoming connection and a run schedule of "%s", so it polls its source '
                          'non-stop. Give it a real interval.' % (p.short_type, period), p.where, p.id)


@rule('NFL005', WARNING, 'hard-coded environment value')
def hardcoded_values(flow):
    for p in flow.processors():
        for name, value in _props(p).items():
            if isinstance(value, str) and HARDCODED.match(value.strip()) and not REFERENCE.search(value):
                yield Finding('NFL005', WARNING,
                              'property "%s" is hard-coded to %s. Move it to a parameter so the same flow can '
                              'run in dev, test and prod.' % (name, _shorten(value)), p.where, p.id)


@rule('NFL006', NOTE, 'processor still has its default name')
def default_names(flow):
    for p in flow.processors():
        if p.name == p.short_type:
            yield Finding('NFL006', NOTE, 'rename "%s" to say what it does (e.g. "Route orders by country"). '
                          'Default names make bulletins and provenance hard to read.' % p.name, p.where, p.id)


@rule('NFL007', WARNING, 'processor is unreachable')
def unreachable(flow):
    targets = {_dest_id(c) for c in flow.connections()}
    for p in flow.processors():
        if p.id not in targets and not p.short_type.startswith(SOURCE_HINTS):
            yield Finding('NFL007', WARNING, '%s has no incoming connection, so it will never receive data.'
                          % p.short_type, p.where, p.id)


@rule('NFL008', NOTE, 'disabled processor left in the flow')
def disabled(flow):
    for p in flow.processors():
        if p.raw.get('scheduledState') == 'DISABLED':
            yield Finding('NFL008', NOTE, 'disabled. Delete it if it is no longer needed.', p.where, p.id)


@rule('NFL009', WARNING, 'large inline script')
def inline_scripts(flow):
    for p in flow.processors():
        body = _props(p).get('Script Body') or ''
        lines = body.count('\n') + 1 if body.strip() else 0
        if lines > 60:
            yield Finding('NFL009', WARNING,
                          'inline script is %d lines. Keep it in a file under version control with tests, and '
                          'point Script File at it.' % lines, p.where, p.id)


@rule('NFL010', NOTE, 'deeply nested process group')
def nesting(flow):
    for g in flow.groups():
        if g.depth > 4:
            yield Finding('NFL010', NOTE, 'nested %d levels deep, which is hard to navigate and to version '
                          'separately.' % g.depth, g.path, g.id)


@rule('NFL011', ERROR, 'connection points at a missing component')
def dangling(flow):
    for c in flow.connections():
        for end in ('source', 'destination'):
            ref = c.raw.get(end) or {}
            # Ports in other groups aren't in this group's lists, so only check same-group processors and funnels
            if ref.get('type') in ('PROCESSOR', 'FUNNEL') and flow.component(ref.get('id')) is None:
                yield Finding('NFL011', ERROR, 'connection %s %s does not exist' % (end, ref.get('id')), c.group_path, c.id)


def _dest_id(c):
    return (c.raw.get('destination') or {}).get('id')


def _connection_label(flow, c):
    src = flow.component((c.raw.get('source') or {}).get('id'))
    dst = flow.component(_dest_id(c))
    rels = ', '.join(c.raw.get('selectedRelationships') or []) or 'queue'
    name = lambda x: (x.name or x.short_type or x.kind.lower()) if x else '?'
    return '"%s" (%s -> %s)' % (rels, name(src), name(dst))


def _shorten(value, n=60):
    return value if len(value) <= n else value[:n - 1] + '…'


def run(flow, disabled_rules=()):
    findings = []
    for rule_id, (_, _, fn) in sorted(RULES.items()):
        if rule_id not in disabled_rules:
            findings.extend(fn(flow))
    order = {ERROR: 0, WARNING: 1, NOTE: 2}
    return sorted(findings, key=lambda f: (order[f.severity], f.rule, f.where))
