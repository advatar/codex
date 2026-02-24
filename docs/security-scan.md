# Security Scan

Codex provides a first-class security scan workflow:

```shell
codex security scan
```

The command runs in scan-only mode and is designed to be safe by default:

- read-only sandbox
- no approvals
- web search disabled
- patch proposals only (no auto-apply)

## Output formats

```shell
codex security scan --format md
codex security scan --format json --out findings.json
codex security scan --sarif findings.sarif
codex security scan --format all --out ./scan-output
```

## Scope and thresholds

```shell
codex security scan \
  --scope src \
  --exclude 'target/**' \
  --severity-floor high \
  --confidence-floor 0.8
```

## Notes

- `--apply` is reserved for future interactive fix workflows.
- SARIF output follows SARIF 2.1.0 and can be consumed by code scanning pipelines.
