# PROMPTS
> Honest status: this file was started with the project. Entry 1 below really happened while building this scaffold with Claude. **Entries 2 to 5 are templates: replace them with your own real events, with real commit links.** Do not submit invented entries; you will be asked about them.

## Reused context (paste into the tool at the start of every session)
```
You are helping build TrustVault (FastAPI + SQLite). Rules for every change:
1. Every route touching a document must call app/authz.py:authorize() and nothing else may decide access.
2. Refusals are audited before the error is raised. Unauthorised and missing return the same 404.
3. Never add caching of auth decisions, JWTs or signed URLs; revocation must be effective on the next request.
4. For any new endpoint, also write a test where a different user is refused, and add it to THREATS.md.
5. After writing tests, list which authz line each test would fail without.
```

## Entry 1: 2026-11-04 (authorisation tests)
- **Asked:** write tests proving one user cannot reach another's documents, plus a mutation script that removes one check at a time.
- **Produced:** 24 passing tests and a 5-mutation script.
- **What was wrong:** the first run showed 2 of 5 mutations *survived*: removing the `role != "admin"` exclusion in `authorize()` and removing `AND u.active=1` from the session query broke nothing. The tests looked thorough but each of those checks was masked by another layer (admin owns nothing and has no grants; disabling a user also deleted their sessions). A third survivor persisted after my first fix, because my "promoted owner" test was still covered by `is_owner` requiring role=owner; only a stale *grant* on a promoted admin isolates it.
- **What I did instead:** added three tests that bypass the masking layer (set the DB flag directly without deleting sessions; promote a user who holds a stale grant). All 5 mutations now caught. Commit: `<link>`

## Entry 2: YYYY-MM-DD (audit trail) , TEMPLATE
- **Asked:** 
- **Produced:** 
- **What was wrong (specific, quote the line):** 
- **What I did instead:** `<commit link>`

## Entry 3: YYYY-MM-DD (authorisation or access control) , TEMPLATE
## Entry 4: YYYY-MM-DD , TEMPLATE
## Entry 5: YYYY-MM-DD , TEMPLATE

Places to look for genuine AI errors in this codebase: does any new route skip `authorize()`; does a refused request audit before raising; does search filter in SQL rather than after fetching; does any response differ between "missing" and "forbidden"; are error messages or timing revealing; does a grant survive a role change.
