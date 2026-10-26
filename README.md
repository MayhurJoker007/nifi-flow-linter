# nifilint

![CI](https://github.com/MayhurJoker007/nifi-flow-linter/actions/workflows/ci.yml/badge.svg)

A linter for Apache NiFi flows. Point it at a flow definition (downloaded from the UI or the registry)
or at `conf/flow.json.gz`, and it reports the patterns that cause production incidents, before they get
deployed.

NiFi flows are code, but they rarely get reviewed like code. A flow can be completely valid and still lose data
every day without anyone noticing. Most of these rules come from problems I've run into building and
supporting NiFi integrations.

```
$ nifilint flows/order-sync.json

NFL001  error   flows/order-sync.json  Order sync > Send to ERP
         Failure, No Retry, retry relationships are auto-terminated: failed FlowFiles are silently deleted.
         Route them somewhere visible (a funnel, a dead-letter queue or an alert).
NFL002  error   flows/order-sync.json  Order sync > List order files
         property "Password" holds a literal value that looks like a secret. Use a sensitive parameter
         (#{...}) so it is encrypted and not exported.
NFL003  warning flows/order-sync.json  Order sync
         back pressure is switched off on "success" (ConvertRecord -> Send to ERP). If the next step stops,
         this queue grows until the content repository fills the disk.
NFL004  warning flows/order-sync.json  Order sync > List order files
         ListSFTP has no incoming connection and a run schedule of "0 sec", so it polls its source non-stop.
```

## Rules

| Rule | Level | Catches |
|---|---|---|
| NFL001 | error | `failure` / `retry` / `No Retry` auto-terminated, so errors are silently deleted |
| NFL002 | error | a secret-looking property (password, token, api key...) with a literal value instead of a parameter |
| NFL003 | warning | back pressure off (0 objects / 0 B) or set absurdly high |
| NFL004 | warning | a source processor (List*, Get*, Query*...) on a 0 sec timer |
| NFL005 | warning | hard-coded URLs, JDBC strings, hosts and paths that should be parameters |
| NFL006 | note | processors still called `UpdateAttribute`, `ConvertRecord`... |
| NFL007 | warning | a non-source processor with no incoming connection |
| NFL008 | note | disabled processors left lying around |
| NFL009 | warning | inline scripts over 60 lines (they belong in a file with tests) |
| NFL010 | note | process groups nested more than 4 deep |
| NFL011 | error | connections pointing at components that don't exist |

`nifilint --list-rules` prints the same list.

## Tested on a real flow

[`examples/ecommerce-report-demo.json`](examples/ecommerce-report-demo.json) is a real flow definition
exported from a NiFi 2.12 instance (the [e-commerce report flow](https://github.com/MayhurJoker007/nifi-ecommerce-report-flow),
with personal details replaced).

The first run against it flagged `SMTP Auth = true` and `Authorization Mode = Use Password` as plaintext
secrets. Both are settings *about* authentication, not secrets. So NFL002 now skips names that describe a
mode, type or setting, and values like `true`/`false`. On the real flow it now reports three warnings: the script
paths are hard-coded, which they are.

## Usage

```
pip install .
nifilint flows/*.json
nifilint flow.json.gz --disable NFL006,NFL008
nifilint flows/*.json --fail-on warning          # stricter gate
nifilint flows/*.json --format json
nifilint flows/*.json --format sarif > nifilint.sarif
```

The exit code is 1 when there are findings at or above `--fail-on` (default `error`), 2 if a file can't be
read, and 0 otherwise.

### In CI

SARIF output plugs into GitHub code scanning, so findings show up in the Security tab and on pull requests.
This repo's own workflow does it on the example flow:

```yaml
- run: nifilint flows/*.json --format sarif > nifilint.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: nifilint.sarif
```

The report never repeats a secret's value, only the property name, because CI logs are not a safe place
for passwords.

## Tests

```
pip install -e .[test]
pytest
```

The tests use a fixture flow with one of each problem. They also cover the `flow.json.gz` format, nesting,
long scripts, exit codes, `--disable`, and that the SARIF output is valid.
