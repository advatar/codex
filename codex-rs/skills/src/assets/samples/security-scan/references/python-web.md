# Python Web Security Focus (FastAPI / Flask / Django)

Review for:

- SQL injection through string-built queries and raw SQL execution.
- SSRF with unvalidated outbound `requests`/HTTP clients.
- Insecure deserialization (`pickle`, unsafe YAML loaders).
- Path traversal in file handling endpoints.
- Missing authorization checks beyond authentication.
- Template injection and unsafe rendering paths.

Evidence pattern:

1. External input source.
2. Validation/sanitization controls (or absence).
3. Sensitive sink with impact description.
