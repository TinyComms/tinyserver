# Abuse response

How a community handles abuse without TinyCloud, or anyone else, reading private conversations. This describes what the code in this repository does, which is only the part inside one community server, and says where the rest is policy that no code here can enforce. API details are in [`../server.md`](../server.md#abuse-reports).

## Principles

1. Abuse is handled without routinely inspecting private communications. Nothing in this server reads a conversation to find abuse, scans messages for it, or queues messages for a person to review.
2. There is no hidden monitoring and no decryption mechanism or backdoor. The server holds no key that decrypts an end-to-end encrypted conversation ([`../e2ee-text.md`](../e2ee-text.md)). A report cannot make it hold one.
3. What a moderator knows about a conversation is what a member of it chose to tell them. A report carries evidence only if the reporter's own client sends it.
4. Enforcement metadata (who was reported, what became of it, what was done) is kept apart from communications: separate tables, separate permission, separate retention, and a log that carries ids and transitions and never text.
5. Suspending a community is something TinyCloud can do as the host. It acts on the community as a whole and needs no access to what is in it. Nothing in this repository implements suspension, because it is an operator action on the deployment (stopping the tenant's containers, see [`tenancy.md`](tenancy.md)), not a server feature.
6. This is not a claim that encryption removes legal duties. It does not. It changes what an operator is able to hand over: for an end-to-end encrypted conversation, ciphertext and the metadata the server needs to route it; for a plaintext conversation, what the database holds. Legal duties, and how requests are received and answered, are a matter for TinyCloud's policy and counsel and are outside this repository.

## What is implemented here

A member can report a message, a member, or a channel. Moderators with the `manage_reports` permission (bit 20) can list, read, triage (`open`, `reviewing`, `actioned`, `dismissed`), annotate, and link an enforcement action (a kick, ban or timeout, by its audit-log id) to a report. Owners can place a report on legal hold (`preserve`). Everything is in migration [`0015_abuse_reports.sql`](../../crates/db/migrations/0015_abuse_reports.sql) and `crates/api/src/reports.rs`.

### What a report holds

| Field | Source | Notes |
| --- | --- | --- |
| kind, category | reporter | `message`, `member` or `channel`; `spam`, `harassment`, `hate`, `violence`, `sexual`, `illegal`, `impersonation`, `other` |
| reporter | the session | a link to the reporter's account, removed when they delete it |
| reported person | the server | the member reported, or the author of the message reported. This is the author id the server already has, with or without encryption |
| message, channel, direct ids | the server | where it was. Ids only |
| note | reporter | up to 2000 characters, optional |
| evidence | reporter's client | up to 32 KiB, optional, **unverified** |
| status, resolution time, linked audit ids | moderators | |
| moderator notes | moderators | separate rows, up to 2000 characters each |
| preserve | an owner | the legal hold |

Reporting a message never copies the message. The server checks that the reporter can already read it, so a report is not a way to find out that a message exists, and then stores its id. If the reporter wants a moderator to see what was said, the reporter's client sends it as `evidence`.

### Evidence is voluntary and cannot be verified

For an end-to-end encrypted conversation the reporter's client sends the plaintext the reporter chooses to disclose. The server cannot check it: it has no key, and even for a plaintext conversation it does not compare evidence with the stored message, since that would be reading the conversation. Evidence can be edited, selected to mislead, or invented. A moderator who acts on it is trusting the reporter's word, and the API says so in every place it shows evidence: `evidence_unverified` is `true` on any report that carries evidence, the database refuses a row with evidence and the flag false, and the API doc states it. Moderators should treat evidence as an allegation and look for corroboration that does not depend on it (several independent reporters, the reported person's public behaviour, the ids and times the server does hold).

A reporter who submits nothing leaves a report that is only an id, a category and a note. Moderators can still act on it with what they can see themselves in channels they can read.

### Who can see a report

| Person | Can they see it |
| --- | --- |
| The reporter | No. They get an acknowledgement with an id and a status of `open` and cannot read the report back |
| The person reported | No. They cannot list or read it, and the audit log hides every row about it |
| A moderator who is the person reported | No. The list leaves it out, `GET` and `PATCH` answer `404` as for an id that does not exist, the audit rows are hidden. Enforced in row level security (`reports_select`, `audit_select`), not only in the handlers |
| A moderator (manage_reports) | Yes, including who reported and the evidence |
| An owner | Yes, as a moderator; an owner can also set the legal hold |
| Anyone else, including holders of `view_audit_log` without `manage_reports`, and bots | No |

The reported member never sees who reported, and the server gives them no way to infer it: the report is unreadable to them, nothing is pushed over the live socket, and the audit row written when a report is filed has no actor (the audit log does not say who reported). Moderators do see the reporter. That is a choice: a moderator has to be able to deal with someone who files false reports to harass another member. The cost is that a moderator is trusted not to disclose the reporter, and a report about a person with a friend among the moderators is visible to that friend. A community with few moderators should say who handles reports about whom.

What the server cannot hide: a moderator who acts (a timeout, a kick) may say why; the reported person may guess the reporter from what the report was about, since a report about a direct message was made by the only other person in it; and a report about a direct message tells moderators that the two people talk, which is metadata the server has anyway.

### The audit log

Every state change writes a row, in the same transaction as the change: `report.create`, `report.triage` (from and to), `report.annotate` (the note's id), `report.link` (the audit id and its action), `report.preserve`, `report.unpreserve`, `report.expire` (a count). Rows carry ids and transitions and never evidence, notes or moderator text. Rows whose action starts `report.` are visible only to holders of `manage_reports`, and not to the person they are about, whatever else they can see in the audit log.

### Limits

- Per reporter: 10 new reports an hour and 50 a day, counted in the database so it holds across restarts and instances. Reporting the same thing again while the first is open returns the first and counts for nothing. A refusal is `429 slow_down`.
- Size: evidence 32768 bytes, a note 2000 characters, the whole request 80 KiB on this route only (every other JSON route stays at 8 KiB). Over-long evidence is `413`.
- A report needs a real, visible target. Nothing is stored for a refused request.

### Retention and the legal hold

- `actioned` and `dismissed` reports, and their moderator notes, are deleted `TINYSERVER_REPORT_RETENTION_DAYS` days after they were resolved. The default is 90; the value must be a whole number from 7 to 3650 and `serve` refuses to start on anything else. The floor of 7 keeps the 24 hour rate limit from counting reports that have already been deleted. The existing sweep (at start and every ten minutes) does the deletion and writes one `report.expire` row with the count.
- `open` and `reviewing` reports are not deleted by age. A report nobody has triaged is a backlog, not a retention decision.
- `preserve` is the legal hold. Only an owner can set or clear it. It is audited, it shows on the list, and it suspends deletion for that report. It is the only thing that does. A moderator who is not an owner cannot place or lift one, and a request that tries changes nothing, including any other field in the same request.
- A hold is a decision to keep text that people wrote. It should be placed for a reason (a legal request, an active investigation) and lifted when the reason ends. Nothing in the server expires a hold.

### Account deletion

[`DELETE /v1/me`](../server.md) tombstones an account. What it does to reports is done by a trigger on that tombstoning (so the account deletion function itself is unchanged), and each choice is deliberate:

- A person who made reports ends up with no link to them: `reporter` becomes `null` on every one, held or not. A held report is kept, but not as a record of who reported. On reports that are **not** held, the reporter's own words (note and evidence) are deleted too: they wrote them and are asking to be gone. The report stays with its kind, target, category and status, so moderators can still act on it, and the moderators' notes stay because they are the moderators' record, not the reporter's.
- A person who is the subject of reports loses, from every report about them that is **not** held, the evidence, the reporter's note and the moderators' notes. The report row stays, so the community keeps a record that a report was made and what it led to, without the material. Being deleted does not let a person erase a report that an owner has placed on hold.
- A report on hold is never changed by anyone's deletion, except that a deleted reporter's link is removed.
- The tombstone itself holds no name, email or picture, so an id left on a report identifies no one.
- Deleted accounts do not reach existing backups. See [`../../deploy/backup/README.md`](../../deploy/backup/README.md).

### Logs

No log line carries a note, evidence or a moderator's note. Filing a report logs its kind and nothing else, not who filed it or who it is about. Working a report logs the moderator's id and the report's id. The fields `evidence`, `evidence_text`, `note`, `notes`, `report_text` and `moderator_note` are on the deny list in `crates/server/src/log_policy.rs` as a second line, with a unit test. The API and database code do not emit the text to begin with, and `crates/api/tests/reports_logs.rs` shows that with the log subscriber at `TRACE`, including the database driver's own lines, across success and every refusal. Lengths and shapes are checked in Rust before the database is asked, and again in the database function, so a check-constraint failure, whose Postgres `DETAIL` line prints the failing row, is not reachable from the API. A database error that does reach the log is logged by its message, which does not include that line; this was read from the error type, not proven by a test that forces one.

## What this does not do

- It does not decide what abuse is, and does not tell moderators what to do. The categories are labels.
- It does not stop a determined moderator copying what they can see.
- It does not notify the reported person, offer an appeal, or tell a reporter what became of a report. Those are choices for the community.
- It cannot see inside an end-to-end encrypted conversation to check a report, and it will never be able to.
- A community's operator can read the database of that community, so they can read every report, note and, for a conversation that is not end-to-end encrypted, every message. "Moderators see reports and the operator sees nothing" is not true and is not claimed. [`tenancy.md`](tenancy.md) says who operates what.
- It is not a legal-process system. It has no export for requests and no mechanism for responding to them; a held report is kept, nothing more.
- Everything above covers one community server. Whether TinyCloud, as the host, takes a report about a community, suspends it, or answers a request is policy, written and decided outside this repository.

## Where it is tested

`crates/api/tests/reports.rs` (13 tests) and `crates/api/tests/reports_logs.rs` (1), unit tests in `crates/db/src/reports.rs`, `crates/db/src/perm.rs` and `crates/server/src/log_policy.rs`. Run:

```sh
TEST_DATABASE_URL_MIGRATE=postgres://app_owner:...@127.0.0.1:54340/tinyserver?sslmode=disable \
TEST_DATABASE_URL=postgres://app_runtime:...@127.0.0.1:54340/tinyserver?sslmode=disable \
  cargo test -p api --test reports --test reports_logs
cargo test -p db --lib
cargo test -p tinyserver log_policy
```

Without the two database variables the integration tests skip and pass. Check that the run says 13 and 1 tests and takes tens of seconds.
