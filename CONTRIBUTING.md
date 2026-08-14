# Contributing

## Fastest path: the AI app catalog
`ai-offboard` maps detected principals/apps to known AI tools via
`src/offboard/catalog/apps.json`. Adding one entry is a great first PR:

```json
{
  "name": "Example AI App",
  "matches": ["example-ai-app", "exampleai.onmicrosoft.com"],
  "dlp_tier": "high",
  "notes": "Requests Mail.Read + Files.ReadWrite.All"
}
```

- `name`: human-readable tool name.
- `matches`: list of substrings / service-principal names to match against.
- `dlp_tier`: `low` | `medium` | `high` based on the data it can reach.
- `notes`: what to flag, for the report's remediation step.

## Guidelines
- Python 3.11+, formatted with `ruff`, tested with `pytest`.
- v1 must stay read-only. No mutating Graph calls in the v1 code path.
- Wire new risk rules into `src/offboard/audit/risk.py` with a unit test in
  `tests/test_risk.py`.
- Run `ruff check . && pytest` before opening a PR.
