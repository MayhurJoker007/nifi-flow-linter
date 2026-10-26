"""
nifilint flows/*.json [--format text|json|sarif] [--disable NFL006,NFL008] [--fail-on error|warning|note]

Exit code is 1 when there are findings at or above --fail-on (default: error), so it can gate a CI build.
"""
import argparse
import sys

from . import flow, report, rules

LEVELS = {'error': 0, 'warning': 1, 'note': 2}


def main(argv=None):
    p = argparse.ArgumentParser(prog='nifilint', description='Lint Apache NiFi flow definitions.')
    p.add_argument('files', nargs='*')
    p.add_argument('--format', choices=['text', 'json', 'sarif'], default='text')
    p.add_argument('--disable', default='', help='comma separated rule ids to skip')
    p.add_argument('--fail-on', choices=list(LEVELS), default='error')
    p.add_argument('--list-rules', action='store_true')
    args = p.parse_args(argv)

    if args.list_rules:
        for rid, (sev, title, _) in sorted(rules.RULES.items()):
            print('%s  %-7s %s' % (rid, sev, title))
        return 0
    if not args.files:
        p.error('give at least one flow file')

    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    disabled = {r.strip().upper() for r in args.disable.split(',') if r.strip()}
    worst = None
    per_file = []
    for path in args.files:
        try:
            findings = rules.run(flow.load(path), disabled)
        except (OSError, ValueError) as e:
            print('%s: %s' % (path, e), file=sys.stderr)
            return 2
        per_file.append((findings, path))
        for f in findings:
            worst = f.severity if worst is None or LEVELS[f.severity] < LEVELS[worst] else worst

    if args.format == 'sarif':
        print(report.sarif(per_file))
    else:
        render = report.text if args.format == 'text' else report.as_json
        print('\n\n'.join(render(findings, path) for findings, path in per_file))
    return 1 if worst is not None and LEVELS[worst] <= LEVELS[args.fail_on] else 0


if __name__ == '__main__':
    sys.exit(main())
