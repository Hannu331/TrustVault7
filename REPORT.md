# TrustVault: requirements report
Prepared 7 November 2026. Stack: Python 3.12, FastAPI, SQLite, plain JavaScript frontend. Everything below was checked against the code in this repository.

## 1. Verdict
Every item in the problem statement's "must do" list and all three non-negotiable standards are implemented and covered by automated tests. The three things only the author can supply are listed in section 6 (live URL, demo video, and prompt-log entries 3 to 5).

## 2. Verification evidence (three independent checks)
| Check | What was run | Result |
|---|---|---|
| **1. Tests and sabotage** | `pytest` (all 51 tests), then `scripts/mutation_check.py`: 15 times it breaks one security check in the code and requires the tests to fail | 51/51 passed. 15/15 sabotaged checks caught. The first run caught 1 untested check (owner-role test); a test was added and it is now caught |
| **2. Production rehearsal** | Started a real server (no demo mode, only one admin), ran `scripts/provision.py`, then `scripts/live_check.py` with the generated accounts, then drove the screens in a real browser | 40/40 live checks passed. Each role sees exactly the seed documents it should. No JavaScript errors |
| **3. Clean clone** | Zipped the project, unzipped into an empty folder, created a **new virtual environment**, installed only `requirements.txt`, ran bare `pytest`, ran the host start command from a different folder, ran `live_check` in trial mode, re-ran all 15 sabotage checks | 51/51 passed, 43/43 live checks passed, 15/15 sabotage checks caught |

## 3. The "must do" list
| # | Requirement | How it is met | Evidence |
|---|---|---|---|
| 1 | Authentication, 3+ roles, written down | Administrator, document owner, viewer. Random 256-bit session tokens (only hashes stored), scrypt passwords, login lockout. Rights written in README "Permission model" and `docs/API.md` | `test_login_lockout_after_repeated_failures`, `test_logout_invalidates_token`, role tests |
| 2 | Upload, organise, search, manage | Upload with category; rename and recategorise; replace file (version number); soft delete; download | `test_upload_validation`, `test_admin_can_upload_and_send_a_document_to_any_account` |
| 3 | Per-document permissions, read and edit, to named people | `grants` table: one row per (document, person) holding `read` or `edit`. Viewers and owners can each receive either | `test_viewer_with_edit_can_edit_but_never_upload_share_or_delete` |
| 4 | Owners grant and take back | Share panel, Remove button, effective on the next request. Admin can also remove anyone's access | `test_revoke_grant_takes_effect_on_next_request`, `test_admin_can_remove_anyones_access_immediately_but_not_add_it` |
| 5 | People without a grant cannot read, download, change or delete | Single function `authorize()` on every document route; same 404 for forbidden and missing | `test_stranger_cannot_use_any_document_route`, `test_admin_has_no_access_to_other_peoples_documents_by_any_route` |
| 6 | Audit of uploads, downloads, changes, deletions, permission changes | Hash-chained append-only log. Also records sign-ins, searches and **every refusal** (including with no login and wrong role) | `test_audit_records_successes_and_refusals`, `test_unauthenticated_attempt_on_a_document_is_audited`, `test_role_refusals_are_audited` |
| 7 | Search by name, owner, category, date | One endpoint with all four filters; the access rule is inside the SQL so unauthorised rows are never read | `test_search_returns_only_accessible_documents`, `test_search_filters_and_like_wildcards_and_sql_injection` |
| 8 | Validation of uploads | Extension allow-list (8 types), magic-byte check, 10 MB streamed cap, empty and binary-text rejection, safe stored names, served as attachment with nosniff | `test_upload_validation`, `test_filename_traversal_is_neutralised` |
| 9 | Administrative view of document activity and permission changes | **Access list** (who has read/edit/owner on every document, who gave it, since when, with a Remove button), **Audit trail** (filter by person, action, document, result), **Overview** (24h counters, repeated-refusal list, permission and account changes) | `test_admin_access_list_shows_who_has_what` |
| 10 | Automated tests that one user cannot reach another's documents | 51 tests, each tied to a numbered threat | `tests/test_access.py`, `tests/test_sharing.py` |

## 4. The three non-negotiable standards
| Standard | Design | Evidence |
|---|---|---|
| **One.** Reachable only by someone who was granted it, through any route | The server decides on every request. No URL, link or token confers access by itself. Admins hold no grants and cannot open others' documents. Probed: guessed ids, huge ids, path tricks (`..`, `//`, `%2F`), HEAD and Range requests, mass assignment, stale grants after role changes, direct file and database paths | T1 to T11, T22, T35 to T37; 15/15 sabotage checks caught |
| **Two.** Prove who reached it, including refusals; what stops quiet alteration | Every action and every refusal is a record containing the SHA-256 of the previous record. Database triggers reject UPDATE and DELETE. The admin page recomputes the chain. A fingerprint (latest record number and hash) saved outside the system also exposes deleted newest records | `test_audit_cannot_be_updated_or_deleted`, `test_audit_chain_detects_tampering_by_someone_who_drops_the_trigger`, `test_anchor_detects_deletion_of_newest_audit_records` |
| **Three.** Taking access away works immediately | No JWTs and no signed download links. Session, active flag, expiry, role and grant are re-read from the database on every request. Disabling or changing a user, or changing a password, deletes that user's sessions. Cost: one or two small reads per request; single instance | `test_revoke_grant_takes_effect_on_next_request`, `test_disabling_user_kills_existing_token`, `test_changing_password_ends_all_sessions_and_old_password_stops_working` |

## 5. Sharing rules as specified
| Rule | Status |
|---|---|
| The administrator can upload documents and send them to any account, with read or edit | Done. Uploads, then Share panel lists every non-admin account |
| A list shows who has what and which operations happened | Done. Access list (owner / read / edit, given by, since) and "What was done" (read, edit, grant, remove, refused attempts) |
| An owner can share to any viewer | Done |
| A viewer can only read or edit what was shared with them (no upload, share or delete) | Done |
| Seed data present | Done: `scripts/provision.py` for a real deployment, `scripts/seed.py` for local trials. Five documents showing read, edit, owner-sent, owner-shared and private access |
| Demo documents removable | `scripts/purge_documents.py` deletes every document and grant, keeps accounts and the audit trail, and records the purge |

## 6. Hand-in checklist
| Item | Status |
|---|---|
| Public Git repository with history across days | Needs you: commit in stages on real dates and push |
| Live URL with seed data | Needs you: deploy (README "Operations"), run `scripts/provision.py`, put the URL in the README |
| Credentials for one account of each role | Built: three random, expiring evaluator accounts; passwords go in a private file, not the public repo (decide how to supply them with the submission) |
| `THREATS.md` | Done: 37 threat entries, 17 knowingly accepted risks, every test it names exists |
| `PROMPTS.md` (5+ dated entries, 2+ on access control or audit) | Partly: entries 1 and 2 are real; **entries 3 to 5 must come from your own AI sessions** |
| Automated tests incl. cross-user tests | Done |
| Database schema and setup scripts | `db/schema.sql`, `scripts/bootstrap.py`, `scripts/provision.py`, `scripts/seed.py` |
| Deployment instructions | README "Operations" and `Dockerfile` |
| API documentation, who may call each endpoint | `docs/API.md` (24 endpoints) |
| Five-minute demo video | Needs you |
| Short write-up (built, not built, permission model, AI use, unfinished) | README |

## 7. Design decisions the brief asks about
- **Permission model:** per-document grants plus three roles (no groups or folders: every inherited permission is another place to leak).
- **File storage:** files live outside the web root under random 32-character names; the database holds the real name; every download goes through `authorize()` and is checked against a stored SHA-256.
- **Taking access away:** see standard three.
- **Audit protection:** see standard two.
- **Administrator:** manages people, sees the Access list and Audit trail, removes access, can upload and send own documents, but **cannot** open other people's documents.
- **Worth noticing:** anyone refused three or more times in 24 hours, every permission or account change, and any audit-chain failure.

## 8. Deliberately not built
Groups and folder inheritance; external guest sharing; version history and restore (soft delete exists); retention rules; MFA; emailed password reset; malware scanning; encryption at rest; the optional AI "who should see this" suggestion (it would have to be suggest-only with the owner confirming and both recorded; left out to keep the permission core small).

## 9. Known gaps (also in THREATS.md, "Accepted")
The audit chain cannot stop someone who rewrites every record and never saved a fingerprint. An administrator can reset a user's password and so impersonate them (audited, not prevented). Login throttling is in memory, so run one instance. Demoting an owner leaves their documents unmanageable. Shared evaluator logins could be changed by one judge (they expire automatically). Backups hold documents unencrypted.

## 10. Reproduce
```
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -q                          # 51 passed
python -m scripts.mutation_check   # 15 CAUGHT
```
