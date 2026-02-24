# Node.js / Express / Nest Security Focus

Review for:

- Command injection (`child_process*`, shell interpolation).
- SQL/NoSQL injection via string concatenation or unsafe operators.
- SSRF via unvalidated outbound URLs.
- Path traversal on file reads/writes and static file serving.
- Missing authz checks on protected routes and service methods.
- Prototype pollution from unsafe object merges.

Evidence pattern:

1. User-controlled source.
2. Data transformation path.
3. Dangerous sink.
4. Why existing guards are insufficient.
