# TrustVault

Secure document sharing where the server decides every access and every attempt, allowed or refused, is recorded in a hash-chained audit trail.
Python 3.12, FastAPI, SQLite, vanilla JS frontend served by the same app.

## Run (clean clone)
```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m scripts.seed          # LOCAL TRYING ONLY: trial accounts and sample documents with published passwords. Never run on a real system
uvicorn app.main:app --port 8000   # open http://localhost:8000
pytest -q                        # 51 tests
python -m scripts.mutation_check # breaks 15 security checks one at a time; every one must make a test fail
```
Docker: `docker build -t trustvault . && docker run -p 8000:8000 -v tv:/data trustvault`
Deploy: any host that runs the Dockerfile (Render, Fly, Railway). Mount a persistent volume at `/data`, put it behind HTTPS, and set `TV_PW_ADMIN`, `TV_PW_ALICE`, `TV_PW_BOB`, `TV_PW_VERA` before the first start to override the demo passwords. **Run one instance only** (see THREATS T20).

Full requirements report with evidence: [REPORT.md](REPORT.md). Threats: [THREATS.md](THREATS.md). API: [docs/API.md](docs/API.md).

## Live system
**URL: https://YOUR-LIVE-URL** (production deployment, HTTPS, persistent storage, no demo mode)

### Evaluation access
This repository is public, so the evaluator **passwords are not published here**. They are supplied privately with the submission (a one-page file, `evaluator-credentials.txt`, generated on the owner's own computer). There is one account per role, with strong random passwords; they **switch off automatically** on the date stated in that file (default 14 days after provisioning), so a leaked login stops working by itself. Please do not change their passwords.

| Role | Username |
|---|---|
| Administrator | evaluator.admin |
| Document owner | evaluator.owner |
| Viewer | evaluator.viewer |

Seed data (created by `scripts/provision.py`, every kind of access): `company-handbook.txt` is sent by the administrator (owner can **edit**, viewer can **read**); `supplier-contract.txt` is owned by the evaluator owner and shared with the viewer (**edit**); `security-policy.txt` is owned by a second owner, `finance.owner`, and shared read-only with the viewer. `board-pack-q3.txt` and `salary-review-2026.txt` belong to `finance.owner` (nobody holds that password) and are **not** shared with any evaluator, so there are private documents to try to reach.

Suggested first checks: as the viewer, try to open, edit, delete or find the two private Finance documents by any route; as the administrator, upload a file and send it to the viewer as read, upgrade it to edit, then remove it and use the viewer's already-open session; then read the refusals and the integrity banner on the administrator's Access list and Audit trail pages. A scripted version: `python -m scripts.live_check URL --admin U:P --owner U:P --viewer U:P` (40 checks).

## Permission model (in my words)
Roles say what you may do in general. Grants say what you may do to one document. Three roles:

| | Administrator | Document owner | Viewer |
|---|---|---|---|
| Upload documents | yes | yes | no |
| Send (share) own documents to any account, as **read** or **edit** | yes | yes | no |
| Take access back from people on their own documents | yes | yes | no |
| Read or edit documents someone shared with them | no (cannot be granted anything) | yes | yes (read or edit, as granted) |
| Delete or share a document they were only given | no | no | no |
| Open, edit, share or delete **other people's** documents | **never** | never | never |
| Remove anyone's access to any document (for example when someone leaves) | yes, immediately, audited | own documents only | no |
| See who has what access on every document, and every operation | yes (Access list, Audit trail) | activity on own documents | no |
| Create, disable and reset accounts, approve or reject sign-up requests | yes | no | no |

A document is reachable only if you uploaded it (as owner or administrator) or hold a grant on it. The **grant** is the right: `read` lets you read; `edit` lets you read and edit (rename, change category, replace the file). Owners and viewers can both receive either right; administrators never receive grants, so they cannot see content they did not upload. Authorisation is one function, `app/authz.py:authorize`, called by every document route, and search applies the same rule inside its SQL. Unauthorised and non-existent documents return the same `404`. Refusals are audited.

## Sign-up and approval
Anyone can open **Create an account** on the sign-in page and ask to be a viewer or an owner (never an administrator). The account starts as `pending`: it cannot sign in, does not appear in the "share with" list and cannot be given any document. An administrator sees the request on **Overview** and **People**, picks the final role, and approves or rejects it (both audited: `signup_requested`, `user_approved`, `user_rejected`). Once approved, the person appears in every owner's and administrator's "share with" list. Sign-ups are throttled (5 per hour per IP, 100 waiting at most). There is no email check, so the administrator should only approve people they recognise (THREATS A18).

## Revocation: what "immediately" means, and what it costs
Sessions are opaque random tokens whose hashes are stored server-side; there are no JWTs and no signed download URLs. Every request re-reads the session, the user's active flag and role, and the grant from the database. Removing a grant, disabling a user or changing a role takes effect on the very next request; disabling or changing a user also deletes all their sessions. Cost: one or two small DB reads per request, and no horizontal scaling without a shared DB. Not revocable: bytes a person already downloaded.

## Audit trail
Append-only table (SQLite triggers reject UPDATE/DELETE) where each record contains the SHA-256 of the previous one. Someone with raw database access could drop the triggers, but editing or deleting any row then breaks the chain, which the admin page verifies (`/api/admin/audit/verify`, tested). The chain alone cannot see the newest records being deleted, so the admin page shows a fingerprint (latest record number and hash). Save it outside the system (email it to yourself daily); checking it later detects deleted tail records (tested). Still not stopped: someone who recomputes every hash AND the saved fingerprint was never kept (THREATS A1).

## Operations (real deployment)
Production is the default. `TV_DEMO=1` exists only for local trials. Provisioning a new production system: set the variables below, deploy, then run `python -m scripts.provision https://YOUR-URL [days]` from your own computer (it asks for your admin login, writes the evaluator passwords to a git-ignored local file, and sets them to expire). Settings:

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
