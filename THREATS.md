# THREATS
"Test" names are in `tests/test_access.py`. Status: Closed / Reduced / Accepted.

| # | Threat | What I did | Test | Status |
|---|---|---|---|---|
| T1 | IDOR: guess another document id on any route | Every document route calls `authorize()`; no lookup by id alone | `test_stranger_cannot_use_any_document_route` | Closed |
| T2 | Unauthenticated / forged token | Opaque 256-bit tokens, hash stored, DB lookup every request | `test_unauthenticated_and_garbage_tokens` | Closed |
| T3 | Direct file or database fetch via static route or path tricks | Blobs stored outside web root under random names; static mount is only `app/static` | `test_no_direct_file_access_via_static_or_paths` | Closed |
| T4 | 403 vs 404 reveals a document exists | One 404 for missing and forbidden | `test_missing_and_forbidden_look_identical` | Closed |
| T5 | Read grant used to edit, delete or re-share; viewer given edit | Separate actions; owner-only actions; role gate on edit | `test_read_grant_cannot_edit_delete_or_share`, `test_viewer_cannot_upload_or_be_given_edit` | Closed |
| T6 | Revoked user keeps access (old token, cached page) | No JWTs or signed URLs; grant, active flag and role re-read per request; sessions deleted on user change | `test_revoke_grant_takes_effect_on_next_request`, `test_disabling_user_kills_existing_token`, `test_session_dies_when_role_changes`, `test_logout_invalidates_token` | Closed (not for bytes already downloaded) |
| T7 | Deleted document still fetchable by grantees | `deleted_at` checked inside `authorize()` | `test_deleted_document_unreachable_even_for_grantees` | Closed |
| T8 | Search leaks titles, owners or counts of unauthorised docs | Access rule is in the SQL `WHERE`; LIKE wildcards escaped; params bound; dates validated | `test_search_returns_only_accessible_documents`, `test_search_filters_and_like_wildcards_and_sql_injection` | Closed |
| T9 | Admin reads content | Admin refused in `authorize()` and returns nothing from search | `test_admin_cannot_read_or_search_content` | Closed, but see T17 |
| T10 | Stale grant after role change (grantee promoted to admin; owner promoted to admin) | `authorize()` re-checks role, independent of ownership/grant rows | `test_grantee_promoted_to_admin_loses_content_access`, `test_promoted_admin_who_still_owns_documents_cannot_read_them` | Closed |
| T11 | Privilege escalation / mass assignment | Pydantic `extra="forbid"`; role changes admin-only; admin cannot edit self | `test_mass_assignment_rejected`, `test_non_admin_cannot_reach_admin_endpoints`, `test_cannot_grant_to_admin_or_self` | Closed |
| T12 | Disabled flag bypassed if session deletion fails | Session query also requires `active=1` | `test_disabled_flag_alone_blocks_token_even_if_sessions_survive` | Closed |
| T13 | Upload abuse: HTML/SVG XSS, MIME spoofing, empty/oversized, NUL bytes | Extension allow-list + magic bytes, 10 MB streamed cap, fixed served content-type, `attachment` + `nosniff`, CSP | `test_upload_validation` | Reduced |
| T14 | Path traversal via filename | Storage key is server-generated hex (asserted); name sanitised, kept as metadata only | `test_filename_traversal_is_neutralised` | Closed |
| T15 | Audit altered or deleted | Append-only triggers + hash chain + verification; refused attempts also recorded | `test_audit_cannot_be_updated_or_deleted`, `test_audit_chain_detects_tampering_by_someone_who_drops_the_trigger`, `test_audit_records_successes_and_refusals` | Reduced: see Accepted A1 |
| T16 | Stored file swapped on disk | SHA-256 recorded at write, verified at every download, failure audited | `test_tampered_blob_is_detected` | Closed (detects, does not repair) |
| T17 | Brute force login / username enumeration | 5 failures per 15 min per IP+username, constant-time dummy hash for unknown users | `test_login_lockout_after_repeated_failures` | Reduced: A3 |
| T18 | Stored XSS via filenames in the UI | Frontend builds DOM with `textContent` only; CSP `default-src 'self'` | (manual) | Reduced |
| T19 | CSRF | Bearer header in `fetch`, no cookies, so browsers never attach credentials automatically | structural | Closed |
| T20 | Login throttle is per process | In-memory counters | none | Accepted A3 |

## Accepted (knowingly)
- **A1 Audit rewrite by a privileged insider.** Triggers can be dropped by anyone with DB write access and the whole chain can be recomputed. Partial edits are detected; a full rewrite is not. Fix I did not build: publish the head hash to a place the app cannot write (daily email, object store with retention lock). With Postgres I would also use a role without UPDATE/DELETE.
- **A2 Administrator impersonation.** An admin can reset a user's password and log in as them. It is audited (`user_changed`, `password_reset`) and shows in the admin view, but it is not prevented. Real fix: no admin password reset, only an emailed reset link, or two-person approval.
- **A3 Throttle weaknesses.** Counters live in memory (reset on restart, not shared across instances). Behind a proxy every client shares one IP, so an attacker can lock out a named user. I did not trust `X-Forwarded-For`.
- **A4 Session token in `sessionStorage`.** An XSS bug would expose it. I avoided cookies to remove CSRF; CSP and `textContent` reduce XSS chance. HttpOnly cookie plus CSRF token is the alternative.
- **A5 Race on revoke.** A download already streaming when access is removed completes. The window is one request. Bytes already saved cannot be recalled by any system.
- **A6 No encryption at rest, no malware scan, no zip-bomb defence beyond never opening archives server-side.** Recipients' viewers still open DOCX/XLSX.
- **A7 Orphans and retention.** Demoting an owner leaves their documents owned but unmanageable until promoted back; no ownership transfer. Soft-deleted blobs are kept forever; no retention or purge.
- **A8 Edit-grant holders can replace content** and the old version is not kept (the replacement and both hashes are audited).
- **A9 Audit contains filenames and search text**, which may be sensitive; admins can read them.
- **A10 Login-failure audit flooding.** Unauthenticated failures are logged without a global rate limit.
- **A11 Multipart bodies are buffered by the framework** before my size check; a Content-Length guard catches honest oversize requests only.
- **A12 Owners can list all non-admin usernames** (needed to share). Username enumeration among staff.
