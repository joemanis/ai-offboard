$ pip install -e ".[dev]"
$ ruff check .
$ pytest

# Then configure (see docs/connectors.md):
$ export OFFBOARD_CLIENT_ID=...
$ export OFFBOARD_CLIENT_SECRET=...
$ export OFFBOARD_AUTHORITY=https://login.microsoftonline.com/<tenant-id>

$ offboard audit --tenant <tenant-id>
$ offboard plan --user jdoe@example.com
```
