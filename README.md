# TrustVault

Secure document sharing where the server decides every access and every attempt, allowed or refused, is recorded in a hash-chained audit trail.
Python 3.12, FastAPI, SQLite, vanilla JS frontend served by the same app.

## Run (clean clone)
```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m scripts.seed          # builds the database from db/schema.sql, adds demo users and 2 documents
uvicorn app.main:app --port 8000   # open http://localhost:8000
pytest -q                        # 41 tests
python -m scripts.mutation_check # breaks 13 security checks one at a time; every one must make a test fail
```
Docker: `docker build -t trustvault . && docker run -p 8000:8000 -v tv:/data trustvault`
Deploy: any host that runs the Dockerfile (Render, Fly, Railway). Mount a persistent volume at `/data`, put it behind HTTPS, and set `TV_PW_ADMIN`, `TV_PW_ALICE`, `TV_PW_BOB`, `TV_PW_VERA` before the first start to override the demo passwords. **Run one instance only** (see THREATS T20).

## Demo accounts (seed data; change on any real deployment)
| Role | Username | Password |
|---|---|---|
| Administrator | admin | admin-Demo-2026! |
| Document owner | alice | alice-Demo-2026! |
| Document owner | bob | bob-Demo-2026! |
| Viewer | vera | vera-Demo-2026! |

Try: log in as `vera`, open alice's salary letter (read granted). As `bob`, search for it: not visible. As `alice`, remove vera's access, then use vera's still-open tab: refused on the next click.

## Permission model (in my words)
Roles say what you may do in general. Grants say what you may do to one document.
- **Administrator**: manages people, sees document *metadata*, audit and activity. **Never** reads, downloads or searches content, even if promoted later while holding old grants.
- **Owner**: uploads; has full control of documents they own (share, revoke, delete, edit, see per-document audit); can be granted `read` or `edit` on others' documents.
- **Viewer**: read-only by role. Can only receive `read` grants. Cannot upload.
- Per-document grants only: no folders, no groups (see "Not built"). A document is reachable only if you own it (as an owner) or hold a grant row. Authorisation is one function, `app/authz.py:authorize`, called by every document route, and search embeds the same rule in its SQL.
- Unauthorised and non-existent documents return the same `404`. Refusals are audited.

## Revocation: what "immediately" means, and what it costs
Sessions are opaque random tokens whose hashes are stored server-side; there are no JWTs and no signed download URLs. Every request re-reads the session, the user's active flag and role, and the grant from the database. Removing a grant, disabling a user or changing a role takes effect on the very next request; disabling or changing a user also deletes all their sessions. Cost: one or two small DB reads per request, and no horizontal scaling without a shared DB. Not revocable: bytes a person already downloaded.

## Audit trail
Append-only table (SQLite triggers reject UPDATE/DELETE) where each record contains the SHA-256 of the previous one. Someone with raw database access could drop the triggers, but editing or deleting any row then breaks the chain, which the admin page verifies (`/api/admin/audit/verify`, tested). The chain alone cannot see the newest records being deleted, so the admin page shows a fingerprint (latest record number and hash). Save it outside the system (email it to yourself daily); checking it later detects deleted tail records (tested). Still not stopped: someone who recomputes every hash AND the saved fingerprint was never kept (THREATS A1).

## Operations (real deployment)
Two deployments from this one repository, differing only in settings:

| Setting | Judge demo | Real app |
|---|---|---|
| `TV_DEMO` | `1` (creates the demo users and documents above) | unset (nothing with a published password is ever created) |
| `TV_ADMIN_USER`, `TV_ADMIN_PASSWORD` | not needed | your admin's login; password 12+ characters, set only in the host's secret settings, never in git |
| `TV_DB`, `TV_STORE` | `/data/trustvault.db`, `/data/blobs` on a persistent disk | same |

`python -m scripts.bootstrap` runs at every start (see `Dockerfile`): upgrades the database, creates the first administrator only if none exists, seeds demo data only when `TV_DEMO=1`, and fails the deployment loudly if no administrator could be created.
Accounts created or reset by an administrator carry a temporary password and can do nothing but change it on first sign-in (`must_change_password`).
**Backups:** `python -m scripts.backup` writes a consistent `trustvault-<time>.tar.gz` (database snapshot plus files). It holds documents unencrypted: store it privately and test a restore.
**Single instance only** (login lockout counters are in memory) and HTTPS must be provided by the host.

## Project layout
`app/` API code (`authz.py` is the single access decision, `security.py` sessions and roles, `db.py` audit chain, `files.py` upload checks) · `app/static/` frontend · `db/schema.sql` database schema · `scripts/seed.py` setup · `tests/` · `docs/API.md` · `THREATS.md` · `PROMPTS.md`.

## Not built (deliberately)
Groups and folder inheritance (every inherited permission is another place to leak; per-document grants are easy to reason about and test); external/guest sharing; versions history and restore UI (soft delete exists, blobs kept); retention policies; MFA; the optional AI "who should see this" assistant (would have to be suggest-only with the suggestion and the decision audited; skipped to keep the permission core small); malware scanning; encryption at rest.

## Unfinished / honest gaps
See THREATS.md "Accepted". Highest: administrator can reset a user's password and so impersonate them (audited, not prevented); no ownership transfer when an owner is demoted; single-instance login throttle.

## How I used AI
Claude wrote most of the first draft; I used a reusable rules file and a mutation script to check it. Where it was wrong (tests that passed without testing an authorisation check, refusals that were not recorded, a crash on a huge id, API docs left public, a chain that could not see deleted newest records) is logged in `PROMPTS.md` with the fixing commits.
