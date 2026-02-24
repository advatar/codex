# Next.js Security Focus

Review for:

- API route and server action input validation gaps.
- SSR/ISR data leaks across user/session boundaries.
- Auth/session checks missing in route handlers and middleware.
- Unsafe use of headers/cookies when constructing backend requests.
- Sensitive server-only values leaking into client bundles.

Evidence pattern:

1. Request or session-derived source.
2. Route/action processing path.
3. Privileged sink (DB query, internal fetch, file system, token usage).
