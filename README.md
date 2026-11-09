# TrustVault

TrustVault is a web app for sharing confidential documents with named people.
The server decides who can open what, every time, and every attempt, allowed or refused, is written to a log that can't be quietly changed.

I built it for the RISE "TrustVault" challenge. It uses Python, FastAPI, SQLite and plain JavaScript. There is no framework on the front end.

## Try it

**Live site:** https://trustvault7-1.onrender.com

It's on free hosting, so the first page load can take about a minute while it wakes up.


**DEMO LINK : https://drive.google.com/file/d/1kV72FZ8vXo4CZvj3_p2_WhlBUocmWhFq/view?usp=drive_link


**Demo accounts.** The passwords are public on purpose, because this is a demo.

| Role | Username | Password |
|---|---|---|
| Administrator | `admin` | `admin-Demo-2026!` |
| Document owner | `alice` | `alice-Demo-2026!` |
| Document owner | `bob` | `bob-Demo-2026!` |
| Viewer | `vera` | `vera-Demo-2026!` |

Anyone else can press **Create an account** on the sign-in page. They stay "pending" until an administrator approves them (more on that below).

### Sample documents

| Document | Owner | Who can open it |
|---|---|---|
| `salary-letter.txt` | alice | vera can **read** it |
| `supplier-contract.txt` | bob | nobody else, it's private |
| `company-handbook.txt` | admin | alice and vera can **read**, bob can **edit** |

### A few things worth trying
1. Sign in as `vera`. She sees the salary letter and the handbook under **Shared with me**, and she can't see bob's contract.
2. Sign in as `bob` and search for "salary". Nothing comes back, because bob was never given that letter.
3. Sign in as `alice`, open the salary letter and press **Remove** next to vera. Then go back to vera's window and click the file. It is refused straight away, even though she was already signed in.
4. Sign in as `admin` and open **Audit trail**. Vera's refused attempt is there in red, and there's a banner saying the log hasn't been tampered with. **Access list** shows who has read or edit access to every document.

## Run it on your own computer

You need Python 3.12 (newer versions may work too).

**Windows (PowerShell)**
```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:TV_DEMO = "1"
python -m scripts.bootstrap
uvicorn app.main:app --port 8000
```

**Mac or Linux**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export TV_DEMO=1
python -m scripts.bootstrap
uvicorn app.main:app --port 8000
```

Then open http://localhost:8000 and sign in with one of the demo accounts above.
`TV_DEMO=1` is what creates those accounts and the sample documents. Never use it on a real system.

To run the tests:
```
pytest -q                          # 69 tests
python -m scripts.mutation_check   # explained under "Tests"
```

## Who can do what

There are three roles. A role says what you can do in general. A **grant** says what you can do with one particular document.

| | Administrator | Owner | Viewer |
|---|---|---|---|
| Upload documents | yes | yes | no |
| Share their own documents with a named person, as read or edit | yes | yes | no |
| Take access back on their own documents | yes | yes | no |
| Read or edit documents shared with them | no | yes | yes |
| Open, edit, share or delete other people's documents | never | never | never |
| Remove anyone's access to any document | yes | own documents only | no |
| See who has what access, and everything that happened | yes | their own documents | no |
| Create, disable and reset accounts, approve sign-ups | yes | no | no |

In plain words:

- You can reach a document only if you uploaded it, or someone gave you a grant on it.
- A grant is either **read** or **edit**. Edit means you can also rename it, change its category and replace the file. Nobody who was only given a document can delete it or share it on.
- A document is shared with one named person at a time. There's no "everyone" option anywhere.
- The administrator can upload and send out documents like an owner, but can't open anyone else's. They can only take access away, which is useful when someone leaves.

### Signing up
Anyone can ask for an account from the sign-in page, as a viewer or an owner but never as an administrator.
The account starts as pending. It can't sign in, it doesn't show up in anyone's "share with" list, and it can't be given documents.
An administrator sees the request on **Overview** and **People**, picks the final role, and approves or rejects it. Both choices are logged.
There's no email check, so the administrator should only approve people they know. Sign-ups are limited to 5 per hour from one address, and no more than 100 can be waiting at once.
Accounts that an administrator creates, or whose password they reset, get a temporary password. The person can't do anything until they choose their own.

## How it keeps documents safe

The brief sets three rules. This is how I meet each one.

**1. Only the people who were given a document can reach it.**
Hiding a button proves nothing, so every check happens on the server. All document routes go through one function, `authorize()` in `app/authz.py`. Search puts the same rule inside the database query, so documents you can't see are never even counted. If a document doesn't exist and if it exists but isn't yours, the answer is the same `404`, so nobody can use it to find out what exists.
The files themselves are stored outside the web folder under random names. The only way to get one is through the server, and each download is checked against a stored SHA-256 fingerprint to catch a file that was swapped on disk.

**2. I can prove who reached a document, including refused attempts.**
Every action goes into an audit log: uploads, downloads, edits, deletions, grants, removals, sign-ins and searches. Refusals are logged too, even when nobody was signed in.
Each record contains the hash of the record before it, so changing or removing one in the middle breaks the chain. Database rules also refuse any update or delete on that table. The admin page re-checks the whole chain.
One thing a chain can't catch is someone deleting only the newest records. So the admin page shows a fingerprint (the latest record number and hash). If you save it somewhere outside the system, you can check it later and that deletion shows up too.

**3. Taking access away works immediately.**
I didn't use login tokens that carry rights, and downloads don't use long-lived links. On every request the server looks up the session, the user's status and role, and the grant in the database. So removing a grant, disabling someone or changing their password takes effect on their very next request.
The price is one or two small database reads per request, and the app has to run as a single instance. The one thing no system can take back is a file someone has already downloaded.

## What's in it

These are the things the brief asked for:

- Sign-in with three roles, and sign-up with approval
- Upload, categories, rename, replace file, delete (a soft delete), and download
- Read and edit permissions per document, given to named people and taken back by the owner
- Search by name, owner, category and date
- Upload checks: allowed file types only, the file's real contents must match its type, 10 MB limit, safe file names
- An audit trail of uploads, downloads, changes, deletions and permission changes
- An admin area with an overview, the access list, the audit trail and people management
- Automated tests showing one user can't reach another user's documents

## Tests

There are 69 automated tests, in `tests/`. Each one belongs to a numbered threat in `THREATS.md`.
They cover things like guessing another document's id on every route, reusing a token after access is removed, tampering with the audit log, and uploads that lie about their type.

To check the tests actually test something, `python -m scripts.mutation_check` breaks 15 of my security checks one at a time, for example by switching off the access check. Each time, the tests have to fail. If one passes while a check is missing, the test wasn't doing its job. All 15 are caught.

## Files in this repository

| File | What it is |
|---|---|
| `THREATS.md` | The ways I think it could be broken, what I did about each, and the risks I knowingly left (40 threats, 18 accepted risks) |
| `PROMPTS.md` | My log of using AI, including what it got wrong |
| `docs/API.md` | Every endpoint and who is allowed to call it |
| `db/schema.sql` | The database schema |
| `REPORT.md` | A requirement-by-requirement report with test evidence |
| `app/` | The server. `authz.py` is the access decision, `security.py` does sessions and roles, `db.py` is the audit chain, `files.py` checks uploads |
| `app/static/` | The web pages |
| `scripts/` | Setup and helper scripts (`bootstrap`, `seed`, `provision`, `backup`, `purge_documents`, `live_check`, `mutation_check`) |
| `tests/` | The automated tests |

## Putting it online

The `Dockerfile` runs on any host that builds from a Dockerfile (I used Render).

- Put the database and files on a persistent disk mounted at `/data`: `TV_DB=/data/trustvault.db` and `TV_STORE=/data/blobs`.
- For a demo like the live site, set `TV_DEMO=1` so the demo accounts and sample documents exist.
- For real use, leave `TV_DEMO` unset and set `TV_ADMIN_USER` and `TV_ADMIN_PASSWORD` (at least 12 characters) in the host's secret settings, never in git. The first start creates that administrator and nothing else.
- Run **one instance only**. The login limit counters live in memory.
- Use HTTPS. The host provides it.
- `python -m scripts.backup` takes a backup of the database and files. It contains documents unencrypted, so store it somewhere private.

## What I didn't build, and why

- **Groups and folders.** Every inherited permission is another place for access to leak, and I would rather have a model I can fully test.
- **Sharing with people outside the company.**
- **Version history and restore.** Deleting is soft, but there's no restore button.
- **Retention rules, MFA, emailed password resets.**
- **The optional AI "who should see this" suggestion.** It would have to only suggest, with a person confirming, and both steps logged. I left it out to keep the permission core small.
- **Malware scanning and encryption at rest.**

## What's unfinished or weak

I'd rather say these than have you find them. The full list is in `THREATS.md`.

- Someone who can write to the database, and who rewrites every audit record and never had a saved fingerprint checked, could change the log without being noticed.
- An administrator can reset a user's password and then sign in as them. It's logged, but it isn't prevented.
- There's no email check on sign-up. Approval is the only protection.
- If an owner is demoted, their old documents become impossible to manage.
- The login limit counters are in memory, so more than one running copy would each count separately.
- Backups contain unencrypted documents.

## How I used AI

I used Claude to write most of the first draft and to help with tests and scripts. I gave it a short rules file at the start of each session (every document route goes through `authorize()`, refusals are logged before the error is returned, no cached permissions) and checked its work with the mutation script.

It was wrong in ways that matter for this project, and I caught them:

- **Tests that looked thorough but weren't.** Some security checks could be removed without any test failing, because another layer hid the gap. The mutation check showed it, and I wrote tests that remove the hiding layer.
- **Refusals that left no record.** A request with no login, or with the wrong role, was refused but not logged. The brief says refused attempts must be provable.
- **A crash on a huge document id,** and the API documentation pages left open to the public.
- **An audit chain that couldn't see the newest records being deleted.** That's why the saved fingerprint exists.

The full log, with what I asked and what I changed, is in `PROMPTS.md`.
