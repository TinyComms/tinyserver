# Privacy and security documentation

How TinyComms (tinyserver, the community server, and tinyclient, the desktop app) handles private communication, and what a managed service built on it (TinyCloud) can and cannot honestly promise. Written to be true: every claim cites code, a test, a document or says "not verified". Read [`guarantees.md`](guarantees.md) first if you need to know what may be said to a customer; read [`threat-model.md`](threat-model.md) first if you need to know who the adversaries are.

State described: tinyserver `origin/main` at `c4ae28b` (#20: abuse reports, operator suspension and legal hold, tenants, encrypted backups), first written on `ea3cd39` on 2026-10-31 and re-checked against `c4ae28b` on 2026-11-01; tinyclient `26916e9` (read only). The TinyCloud control plane (provisioning, billing, staff tooling) is not in this repository.

## Status words

Used the same way in every document here.

| Word | Meaning |
|---|---|
| Implemented, tested | The code does it and a named test fails if it stops |
| Implemented | The code does it; no test asserts it |
| Designed | Written down, not built |
| In progress | Being built elsewhere, **not merged on main** (`c4ae28b`). Text and attachment end-to-end encryption (E2EE) is the main case: it is specified in [`../e2ee-text.md`](../e2ee-text.md) and nothing about it is verified here |
| Not done | Neither designed nor built |
| Not verified | Could not be checked; the document says what was and was not looked at |

## The five categories

| # | Category | Section of [`guarantees.md`](guarantees.md) |
|---|---|---|
| 1 | Information the server cryptographically cannot decrypt | 1 |
| 2 | Information whose access is operationally restricted | 2 |
| 3 | Information the provider chooses not to collect | 3 |
| 4 | Information necessarily visible to infrastructure providers (Cloudflare, the host, the network) | 4 |
| 5 | Information retained for billing, security or compliance | 5 |

## Documents

| Document | What it answers | Written |
|---|---|---|
| [`guarantees.md`](guarantees.md) | **The matrix.** Every guarantee with status and evidence, what can be advertised today, what must not be claimed | Yes |
| [`threat-model.md`](threat-model.md) | Who the adversaries are (member, owner, Cloudflare, host, operator, other tenant, identity provider, compromised process, client, legal process) and what each can reach | Yes |
| [`data-flow.md`](data-flow.md) | What moves where in sign-in, messages, attachments, calls, moderation, deletion | Yes |
| [`metadata.md`](metadata.md) | Every place data lives: Postgres tables, memory, volumes, backups, logs, Cloudflare, host, Pocket ID, admin tooling, clamd, client | Yes |
| [`network.md`](network.md) | IP handling in HTTP, WebSocket, WebRTC and the SFU; what participants, the SFU host and Cloudflare learn; relay options; limits; what can never be hidden from the host | Yes |
| [`authentication.md`](authentication.md) | OIDC and passkeys, identity, recovery, devices, session revocation, account deletion, cross-community correlation, billing separation | Yes |
| [`encryption-architecture.md`](encryption-architecture.md) | Keys for calls, text and attachments: who holds them and their lifecycle | Yes |
| [`retention-and-deletion.md`](retention-and-deletion.md) | How long each class of data stays; what each deletion path removes and cannot reach; legal holds | Yes |
| [`telemetry-and-logging.md`](telemetry-and-logging.md) | Every log sink, what the default log reveals, where redaction does not apply, telemetry inventory. Extends [`../logging.md`](../logging.md) | Yes |
| [`performance.md`](performance.md) | Cost of the design; **measured numbers are TODO** | Yes, with a TODO table |
| [`migration.md`](migration.md) | Existing plaintext, old and new client and server, schema migration, rollback, backups, moving hosts | Yes |
| [`compliance.md`](compliance.md) | Technical readiness for US and EU duties, each item split into an engineering requirement and a question for counsel. No legal conclusions | Yes |
| [`remaining-risks.md`](remaining-risks.md) | What needs independent review, residual attack surface, assumptions, limits of anonymity and of E2EE | Yes |
| [`findings.md`](findings.md) | The ledger of security and privacy findings and their status, with the corrections from this pass | Existing |
| [`abuse-response.md`](abuse-response.md) | In-community abuse reports: what a report holds, who sees it, retention, the owner's hold, logs | From #20. Two lines corrected here (suspension, a dead link; [`findings.md`](findings.md)) |
| [`tenancy.md`](tenancy.md) | The per-tenant isolation contract, the operator's hooks (suspend, hold, backup, export, restore, delete) and their limits | From #20 |
| `benchmarks.md` | Measured performance numbers | **Not written yet.** Referenced by [`../e2ee-text.md`](../e2ee-text.md) and [`performance.md`](performance.md) |

The link to `benchmarks.md` does not resolve yet.

## Reading order

1. [`guarantees.md`](guarantees.md) for the conclusions.
2. [`threat-model.md`](threat-model.md) for the reasoning.
3. [`metadata.md`](metadata.md) and [`network.md`](network.md) for what exists and who sees it.
4. [`encryption-architecture.md`](encryption-architecture.md) with [`../calls.md`](../calls.md) and [`../e2ee-text.md`](../e2ee-text.md) for the cryptography.
5. [`compliance.md`](compliance.md) and [`remaining-risks.md`](remaining-risks.md) for what is unresolved.

## Existing documents these build on

[`../server.md`](../server.md) (API and permissions), [`../calls.md`](../calls.md) (live socket, SFU, call E2EE), [`../logging.md`](../logging.md), [`../e2ee-text.md`](../e2ee-text.md) (text E2EE specification, not implemented on main), [`../../deploy/README.md`](../../deploy/README.md) (running a community), [`../../deploy/tenant/README.md`](../../deploy/tenant/README.md) (tenants and the operator's hooks), [`../../deploy/tests/README.md`](../../deploy/tests/README.md) (what the shell checks check). tinyclient's `SECURITY.md`, `docs/logging.md` and `docs/architecture.md` were read from the client repository and are cited by name.

## What is verified and what is not

Verified by reading: the sixteen migrations, `crates/api`, `crates/server`, `crates/sfu`, `deploy/compose.yml`, `deploy/tenant/` and `deploy/tests/` at `c4ae28b`, and the test names cited. Not run: the test suite, the shell checks in `deploy/tests/` and the compose stack were not executed for this pass, and CI runs `cargo test` but not `deploy/tests/`. A test named in these documents was confirmed to exist and to assert what is said, by reading it; that is not the same as a green run.

Not verified anywhere in this set: Pocket ID's behaviour beyond its published documentation, Cloudflare's policies, the contents of Postgres, Pocket ID, clamd and cloudflared logs, tinyclient behaviour beyond its own documents and the files cited, and anything that depends on unmerged E2EE code. [`remaining-risks.md`](remaining-risks.md) section 6 lists them.

## Errors found in existing documents

[`findings.md`](findings.md) (last section) lists where `docs/logging.md`, `docs/server.md`, `docs/calls.md`, `deploy/README.md` and tinyclient's `SECURITY.md` disagree with the code. Each row says whether it was fixed in this set (`docs/server.md`, `docs/calls.md`, `docs/e2ee-text.md`, `abuse-response.md`) or only reported.

## Maintenance

A change that adds a table, a column, a log call, an outbound connection, a volume or a container must update [`metadata.md`](metadata.md) and, if it moves a guarantee, [`guarantees.md`](guarantees.md) in the same change. When text E2EE merges, follow [`guarantees.md`](guarantees.md) section 8.
