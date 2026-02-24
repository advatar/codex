# React Security Focus

Review for:

- DOM XSS via `dangerouslySetInnerHTML` and untrusted markdown/HTML rendering.
- Unsafe URL handling (`javascript:` URLs, unvalidated redirects).
- Client-side authz assumptions that must be enforced server-side.
- Secret exposure through bundled environment variables.
- Insecure postMessage usage and origin checks.

Evidence pattern:

1. User-controlled source.
2. Sanitization/encoding step (or missing step).
3. Dangerous sink in JSX/DOM APIs.
