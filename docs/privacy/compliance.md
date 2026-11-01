# Compliance readiness: a technical assessment

What engineering would have to build or decide for a managed TinyCloud service to be able to meet the legal duties that probably apply to it, and the questions that only qualified counsel can answer. **This is not legal advice and states no legal conclusion.** A sentence of the form "the law requires X" is a pointer to a source and an understanding to be confirmed, not a finding. Nothing here says, or should be read to say, that collecting no identity document, collecting little data, or using end-to-end encryption (E2EE) removes any legal obligation: whether and how obligations apply is exactly what the "questions for counsel" are about.

Every item is split into **Engineering requirement** (something the product or the code must do, or a fact counsel will need) and **Question for counsel**. Status words are in [`README.md`](README.md). Text E2EE is in progress; where it matters the item says so. Related: [`abuse-response.md`](abuse-response.md) (the procedure for reports and orders, written separately), [`tenancy.md`](tenancy.md), [`retention-and-deletion.md`](retention-and-deletion.md), [`metadata.md`](metadata.md), [`guarantees.md`](guarantees.md) (category 5).

**Sources consulted (2026-10-31).** [18 U.S.C. § 2258A](https://www.law.cornell.edu/uscode/text/18/2258A), [17 U.S.C. § 512](https://www.law.cornell.edu/uscode/text/17/512), [18 U.S.C. § 2703](https://www.law.cornell.edu/uscode/text/18/2703), Regulation (EU) 2022/2065 (the Digital Services Act, DSA) at [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2022/2065/oj/eng) (article titles and section placement checked on a secondary index; recital 14 on a secondary site; article text itself not reviewed here), the GDPR (Regulation (EU) 2016/679, article numbers from the author's knowledge, not re-fetched). Statutes change; the 2024 and 2025 amendments to § 2258A are visible on the page cited.

## 1. What TinyCloud technically is

Facts counsel will need, from the code and compose file:

| Fact | Detail |
|---|---|
| What it stores for customers | Communities: members, text messages (plaintext today; ciphertext for encrypted conversations once E2EE ships), attachments, avatars, audit records. [`metadata.md`](metadata.md) |
| Who decides who is in a community | The community's owner and administrators, by invite or, if configured, by IdP group (`TINYSERVER_OIDC_MEMBER_GROUPS`, which admits without a human decision). The default is invite only |
| Is anything publicly readable? | No unauthenticated read of content exists: every message, channel and media route needs a member session or a signed URL tied to one (`docs/server.md`). There is no public web view, no search engine surface, no anonymous guest (`docs/calls.md`, "Guests without an account? No.") |
| Real-time voice and video | Between members through a server-side forwarder (SFU), no connection to the public telephone network (no SIP or PSTN code exists in `crates/`) |
| What the operator can read | Plaintext today for non-E2EE data; ciphertext and metadata for E2EE content ([`threat-model.md`](threat-model.md) 3.7) |
| What the operator can do to a community | With `deploy/tenant/operator.sh` (#20): suspend it read-only or offline with a notice, resume it, place and release a legal hold, back it up encrypted, export it to the owner, restore it, delete it ([`tenancy.md`](tenancy.md)). Also: start and stop stacks and read the database. These are shell hooks on the host; the TinyCloud control plane that would call them is not in this repository |
| What it cannot do | Read call audio in an E2EE call; read encrypted text (**in progress**) |
| Where data sits | One stack per tenant on a host: Postgres, uploads, Pocket ID. Cloudflare terminates TLS. Media goes straight to the host |
| Identity of customers | Not built. Two populations: a **payer** (the customer of TinyCloud) and **members** (people in communities). Often the same person, but the system must not assume it |

## 2. United States: provider duties for child sexual abuse material (18 U.S.C. § 2258A)

My understanding of the text on the cited page: a "provider" that obtains **actual knowledge** of facts from which there is an apparent violation of the listed child-exploitation statutes must report to the National Center for Missing and Exploited Children's CyberTipline "as soon as reasonably possible", must send its contact details to NCMEC, and may include identifying information, the content and transmission data at its discretion (§ 2258A(a), (b)). The statute does not require monitoring users, monitoring communications, or affirmatively searching, screening or scanning (§ 2258A(f)). A submitted report is treated as a request to preserve the contents for one year (the period was 90 days before the 2024 amendment, Pub. L. 118–59), in a secure location with limited employee access (§ 2258A(h)). Fines for knowing and willful failure to report are set in the statute. The definition of "provider" lives in another section (§ 2258E) that was **not retrieved** here.

| Engineering requirement | Question for counsel |
|---|---|
| An intake path for reports from members, owners and third parties, with a record of when it arrived. **Built inside a community only**: `POST /v1/reports` lets a member report a message, member or channel to that community's moderators, with `created_at` and a `report.create` audit row (`0015_abuse_reports.sql`, [`abuse-response.md`](abuse-response.md)). Reports go to the community's moderators, not to TinyCloud. **Not built**: an intake for third parties or non-members, and any path from a report to TinyCloud | Is TinyCloud a "provider" for § 2258A, and for which of its services? Is a community owner also one? Does knowledge by a community's moderators, through an in-community report, count as TinyCloud's? |
| A way to determine and record when TinyCloud has "actual knowledge" (what staff saw, what a report contained), because that is the statutory trigger | What counts as actual knowledge for a host that **can** read plaintext conversations but chooses not to look? Does the capability to read matter? Does knowledge by a community administrator count as the host's? |
| The ability to produce what a report may contain and the service holds: account ids, timestamps, email if the account has one, `joined_via`, audit rows, message and attachment content for plaintext conversations. It holds **no IP address** in its database ([`metadata.md`](metadata.md)); Cloudflare and the host's network do | Which of that must or may go in a report; whether Cloudflare, as a separate provider, reports independently; what to do about an address the service does not hold |
| A preservation store: on a submitted report, copy the content provided and "commingled" context to a secure, access-controlled location for one year. **Partly built.** An owner's `preserve` on an in-community report keeps that report (its note and the evidence the reporter sent) through the retention sweep and through account deletion; `tinyserver operator hold` keeps every resolved report and makes `operator.sh` refuse `delete` and `restore` (`0015`, `0016`; tests `the_sweep_deletes_old_resolved_reports_and_keeps_held_ones`, `a_legal_hold_keeps_resolved_reports_and_is_not_shown_to_members`, `deploy/tests/hooks.sh`). **Not built**: a copy of the reported message or attachment (a report stores only ids, and the message can still be deleted), a separate access-controlled store, a one-year timer (a hold lasts until released), and any hold on an account. Message deletion is still immediate and irreversible (`unlink`) ([`retention-and-deletion.md`](retention-and-deletion.md), [`findings.md`](findings.md) N12) | Whether preservation must also cover backups; whether an owner's in-community hold is TinyCloud's preservation; how to reconcile with a person's erasure request (section 7) |
| For E2EE conversations (**in progress**) the server holds ciphertext and metadata only, and cannot see content. Content could reach TinyCloud through a member who reports and supplies it. The server must not claim to scan sealed attachments (specified) | How the statute applies when the host cannot read content; whether a report without content, only metadata, satisfies anything; any exposure from offering E2EE. Pending legislation is tracked in section 8.5 |
| Registration with NCMEC and a named contact; training of staff who may see material; a rule that reviewers do not copy it elsewhere | Whether to register before or after launch; employee handling rules; reporting for content in a customer's backups |
| Account actions after a report: suspend the member, or the community (see [`abuse-response.md`](abuse-response.md)). Present tools: kick, ban, timeout and delete channel, each linkable to the report (`link_audit_id`); community suspension, read-only or offline, by `tinyserver operator suspend` (`0016_operator.sql`, tested in `crates/api/tests/operator.rs`). Suspension deletes nothing. Read-only refuses every write except signing in and out, `DELETE /v1/me` and `POST /v1/reports`, so members cannot delete messages but can still delete their accounts (`read_only_still_lets_a_person_sign_out_and_delete_their_account`) | Whether suspension must preserve rather than delete; whether a member may still delete their account while their community is suspended or held |

## 3. United States: copyright notices and the safe harbor (17 U.S.C. § 512(c), (g), (i))

My understanding of the cited text: a service provider that stores material at users' direction is shielded from monetary relief for infringement if, among other conditions, it has no actual knowledge and no "red flag" awareness, acts expeditiously to remove or disable access on a compliant notice, receives no direct financial benefit attributable to infringement where it can control it, has a designated agent whose details are on the service and with the Copyright Office, and adopts and implements a policy of terminating repeat infringers in appropriate circumstances (§ 512(c)(1)–(2), (i)). A compliant notice has six elements (§ 512(c)(3)). On a counter-notice the provider restores the material not less than 10 and not more than 14 business days later unless the complainant files suit (§ 512(g)). There is no duty to monitor (§ 512(m)).

| Engineering requirement | Question for counsel |
|---|---|
| A published contact for notices and a registered designated agent (the registration needs periodic renewal; the interval was not checked here) | Whether TinyCloud, the community owner, or both need to register; whether registration should be in the company's name |
| A way to **disable access to specific material** identified by a notice: for plaintext conversations, a message or attachment id. Present tooling can only delete: the attachment file is `unlink`ed and the message emptied, which is irreversible | Whether deletion rather than disabling is acceptable when a counter-notice may require restoration |
| A **disable-and-retain** state so material can be restored after a counter-notice (10 to 14 business days). Not built for a message or attachment. `suspend --read-only` or `--offline` disables a whole community without deleting it, which is far broader than one item | |
| Handling of counter-notices: forwarding, the clock, restoration. Not built | |
| A repeat-infringer policy and its mechanics: account termination exists per community (kick, ban); termination at the TinyCloud level means tenant suspension (`tinyserver operator suspend --offline`) or `operator.sh delete`. Per-member records of notices must exist to count repeats | What "repeat infringer" means across communities when TinyCloud cannot see member identities across tenants (there is no cross-community link, by design: [`authentication.md`](authentication.md) section 8) |
| Notice handling for E2EE content (**in progress**): the host cannot see the material, a complainant cannot see it either unless a member, and the media URL is signed and short-lived. A notice would have to name a conversation and message id the complainant could only get from a member | Whether the safe harbor is available or relevant for private, closed communities; how to act on a notice the host cannot verify against content |

## 4. United States: stored communications and valid process (ECPA, the Stored Communications Act)

My understanding of § 2703: content of communications is obtained with a warrant (with notice and subpoena routes described for some stored categories); basic records the statute lists in § 2703(c)(2) can be obtained with a subpoena; a government request can require preservation for 90 days, renewable for another 90 (§ 2703(f)). The statute lists these subscriber records: name; address; connection records or **records of session times and durations**; length of service and types of service; telephone or instrument number or other subscriber number or identity, **including any temporarily assigned network address**; and means and source of payment.

| Engineering requirement | Question for counsel |
|---|---|
| A legal-process intake: a published contact, verification of the requester and the order, a ticket with deadlines, and a **disclosure ledger** (what was produced, to whom, under which order) | Whether TinyCloud is an electronic communication service or a remote computing service, and per service (voice, direct messages, channels, storage) |
| **Map the data to the statute's list**. What TinyCloud holds that fits the list: user id, display name and optional email; `memberships.created_at` (start date), `last_seen_at`, session rows with creation and expiry times; **the default operator log, which records when each live socket opened and closed per `user_id`** ([`telemetry-and-logging.md`](telemetry-and-logging.md) section 2), which looks like "session times and durations"; no network address in the database; payer details if billing is built | Whether logs that record socket open and close are "session times and durations"; whether turning logging down is consistent with any retention duty; what to do about an order for addresses the service does not hold |
| **Preservation on request**: freeze a tenant's or a member's records for 90 days renewable. **Partly built, for a tenant only.** `tinyserver operator hold --reason TEXT` (reason kept in `operator_events`, never shown to members) stops resolved reports expiring and makes `operator.sh` refuse `delete` and `restore`. It does not stop members deleting messages, channels or accounts, so it does not freeze a member's records; it has no 90-day clock; and nothing freezes one member. An encrypted `operator.sh backup` taken at the time of the request is a copy that a hold does not prevent ([`findings.md`](findings.md) N12) | Whether a preservation request can be met by copying (a backup); whether the host or the community owner is the right addressee |
| Scope each production to the tenant named in the order. Isolation is [`tenancy.md`](tenancy.md): one database, role pair and volume set per tenant, checked by `deploy/tests/isolation.sh`. `operator.sh export` and `backup` take one tenant at a time | |
| A rule for notifying the customer or member, where the order allows | Notice policy, gag orders, and what TinyCloud may say |
| A statement of what cannot be produced: for E2EE conversations (**in progress**) message text, edits, attachment contents and names. For plaintext conversations and for calls in transport-only mode (not recorded; never stored) the data is plaintext in the database, or not held at all in the case of calls | What TinyCloud may promise customers about what it will refuse, and a policy on requests that are overbroad |
| Emergency disclosure handling | The standard to apply and who may approve |
| Transparency reporting | Whether to publish; the format |

## 5. United States: CALEA

| Engineering requirement | Question for counsel |
|---|---|
| A factual description for counsel: what the voice and chat services are; the SFU relays app media between members and has no gateway to the telephone network; no phone numbers are used; no lawful-intercept interface exists; E2EE calls are sealed by the apps | Does the Communications Assistance for Law Enforcement Act apply to any component of TinyCloud, for example as a provider of interconnected VoIP or of broadband access? The service has no telephone interconnection in code, but applicability is a legal question and was not analysed |
| If an intercept capability were required: the architecture offers plaintext access to database content only for non-E2EE data and nothing for E2EE calls. Building a capability would conflict with the E2EE claims | What the law would require of a service whose design prevents decryption, and when |

## 6. European Union: GDPR roles, rights, erasure and backups

Article numbers below are from the author's knowledge of the GDPR and were not re-fetched. Counsel should confirm each.

### 6.1 Roles

| Processing | Candidate role of TinyCloud | Candidate role of the community owner |
|---|---|---|
| Community content: messages, attachments, member lists, audit log | Processor (Art. 4(8), Art. 28), on the owner's instructions | Controller (Art. 4(7)) toward its members |
| Account and billing data for TinyCloud's own customers | Controller | n/a |
| Security and abuse records TinyCloud keeps for itself (logs, reports) | Controller | n/a |
| Identity provider data (Pocket ID: usernames, passkeys, optional email, IP audit log) in a tenant stack | Unclear: processor if the owner decides, controller or joint controller if TinyCloud administers it | Unclear |
| Data TinyCloud staff can read because of host access | The role depends on purposes and instructions | |

**Question for counsel:** which role applies to each row, whether joint controllership arises, and how roles change when TinyCloud hosts the identity provider on a customer's behalf. This decides who answers a data-subject request, who signs which agreement, and who is liable for a breach.

### 6.2 Engineering requirements that follow whatever the roles are

| Requirement | State |
|---|---|
| Records of processing and a data inventory (Art. 30) | [`metadata.md`](metadata.md) is the technical input |
| Security measures proportionate to risk (Art. 32): encryption in transit and at rest, access control, resilience, testing | In transit: TLS at Cloudflare, DTLS for media. At rest: no encryption in this stack except what the host provides; E2EE for calls (done) and text (**in progress**). Access control: [`threat-model.md`](threat-model.md). No independent test ([`remaining-risks.md`](remaining-risks.md)) |
| Data protection by design and default (Art. 25) | Default invite-only, no passwords, no addresses in the database, minimal logs (with the exceptions in [`telemetry-and-logging.md`](telemetry-and-logging.md)) |
| Breach detection and notice (Art. 33: processors notify controllers without undue delay; controllers notify authorities within 72 hours) | **Not built**: no monitoring, no alerting, minimal logs. Minimising logs reduces detection capability: a trade to decide explicitly |
| Data-subject rights: access, rectification (`PATCH /v1/me` exists), erasure (`DELETE /v1/me` exists, with gaps), restriction, portability, objection | No per-person export exists. `operator.sh export` exports a whole community to its owner, encrypted to the owner's age recipients (`deploy/tests/hooks.sh`); that is portability for a controller, not a subject-access tool. Erasure gaps: Pocket ID account, backups, WAL, logs ([`retention-and-deletion.md`](retention-and-deletion.md)). A subject-access request for E2EE content cannot be fulfilled from the server |
| Sub-processors listed and bound by contract | At least: the hosting provider, Cloudflare, a payment processor, ClamAV signature mirrors (receive the host's address only), any support tooling. None of them is chosen yet |
| Data Protection Officer, representative in the Union where required (Arts. 37, 27), data protection impact assessment (Art. 35) | Not addressed here |

**Questions for counsel:** lawful bases for each processing; whether the default operator log of connection events needs a stated basis and a retention limit; whether a DPIA is required; whether TinyCloud needs an EU representative; what the DPA must say about host access by staff.

## 7. Erasure (Art. 17) against backups and legal holds

| Engineering requirement | Question for counsel |
|---|---|
| A documented erasure procedure listing every store and a time limit for each ([`retention-and-deletion.md`](retention-and-deletion.md) section 3) | Whether a backup retention period of N days is acceptable as the erasure horizon; whether data in backups may be "put beyond use" until overwritten |
| Backups encrypted with a destroyable key, and after any restore a replay of deletions from a minimal ledger of deleted ids. **Half built**: `operator.sh keygen` gives a tenant its own age key and every backup is encrypted to it; `delete` destroys the copy on the host, after which a backup encrypted to that key alone cannot be opened (`deploy/tests/hooks.sh`). Copies of the key kept elsewhere, and the operator's own recipient if a backup was also encrypted to it, keep backups readable. **No ledger and no replay**: a restore brings deleted accounts back ([`findings.md`](findings.md) N11) | Whether the ledger itself is personal data and on what basis it is kept |
| A **legal hold**: freeze deletion for an account or tenant when valid process or a report requires preservation. **Built for a tenant, narrowly**: `tinyserver operator hold` blocks `operator.sh delete` and `restore` and the expiry of resolved reports; an owner's `preserve` holds one report. **Not built for an account**: `DELETE /v1/me` runs under any hold, and on a held report it removes only the reporter's link (`0015`; `crates/api/tests/reports.rs` `a_reporter_deleting_their_account_loses_the_link_and_a_hold_keeps_the_report`, `operator.rs` `read_only_still_lets_a_person_sign_out_and_delete_their_account`) | Whether and when a hold overrides an erasure request (Art. 17(3) lists exceptions, including legal obligations and legal claims; the application is counsel's). The code today lets erasure win for the account and the hold win for the report's own fields |
| Deleting a tinyserver account does not delete the identity-provider account | Whose duty it is to delete the Pocket ID account in a managed tenant |
| For E2EE content: deletion removes the ciphertext from the server and cannot recall plaintext on devices | What to say to customers about erasure of content others hold |

## 8. European Union: the Digital Services Act and related regimes

### 8.1 Classification: three questions

| Question | Facts for counsel |
|---|---|
| **Hosting service.** Does TinyCloud store information provided by a recipient of the service at their request, so that the hosting provisions (Arts. 6, 16, 17, 18) apply? | Yes in a plain technical sense for text and attachments (plaintext today, ciphertext tomorrow). Counsel decides the legal classification, and whether TinyCloud or the community owner (or both) is the provider |
| **Online platform.** Is it a hosting service that disseminates information **to the public** at the recipient's request (the provisions of DSA Chapter III, Section 3: Arts. 19 to 28, including 20, 22, 23)? | Recital 14, as read on a secondary site, says dissemination to the public is making information available to "a potentially unlimited number of persons", and that where access depends on joining a group it counts as public only if people are admitted without "a human decision or selection of whom to grant access"; and that private messaging services fall outside the platform definition. Facts: communities are invite only by default, with a human issuing invites; **group-claim auto-join** (`TINYSERVER_OIDC_MEMBER_GROUPS`) exists and admits automatically; direct messages are between two members; there is no public content surface. A very large community with auto-join is the case to examine |
| **Interpersonal communications service.** Are direct messages and voice calls "number-independent interpersonal communications services" under the European Electronic Communications Code, with the confidentiality duties of the ePrivacy Directive (2002/58/EC) and exposure to the interim derogation and the proposed child-sexual-abuse regulation? | Direct messages and calls are between named members; channels are group conversations among members. The service has no phone numbers. Not analysed |

### 8.2 Obligations to map (the DSA's titles and placement checked on a secondary index; content to be confirmed on EUR-Lex)

| Article | Subject | Applies to (as indexed) | Engineering requirement | Question for counsel |
|---|---|---|---|---|
| 9, 10 | Orders to act against illegal content and to provide information | All intermediary services | A procedure and a contact to receive, check and answer orders; scope to one tenant; a disclosure ledger | Which orders bind a provider that cannot read E2EE content; how to answer an order to act on content it cannot see |
| 11 | Points of contact for authorities, the Commission and the Board | All intermediary services (Section 1) | A public contact, languages, a monitored mailbox | Languages and staffing |
| 12 | Points of contact for recipients | All intermediary services | A public, direct electronic contact for community owners and members, not only an automated bot | |
| 13 | Legal representative | Providers without an EU establishment offering services in the Union | If TinyCloud is not established in the EU: a designated representative and notification to a Digital Services Coordinator | Whether and where to establish; liability of the representative |
| 14 | Terms and conditions | All | Terms stating restrictions and moderation tools, in clear language; changes notified | |
| 15 | Transparency reports | All (with the exemption for micro and small enterprises as indexed) | Counters for notices, actions, orders, complaints. None exist | Size classification and exemption |
| 16 | Notice and action | Hosting services | An electronic notice form that collects an explanation, the exact location of the content (a message or attachment id, a conversation), the notifier's name and email (unless certain offences), a confirmation of good faith; an acknowledgement; a decision notice. For E2EE content the location can be named but not verified | Whether private communications are in scope; handling of notices about content the host cannot read |
| 17 | Statement of reasons | Hosting services (as indexed) | When TinyCloud restricts content or suspends an account or community for illegality or a terms breach, tell the affected recipient what was done, why, on what facts and ground, whether automated means were used, and the redress available. Needs a durable record of every moderation decision (the `audit_log` records actions inside a community, not TinyCloud's own) | What counts as a restriction; what to tell a recipient when a legal order forbids notice |
| 18 | Notification of suspicions of criminal offences | Hosting services (as indexed) | An escalation path to authorities when staff become aware of information giving rise to a suspicion of a serious offence involving a threat to life or safety | The threshold and the authority |
| 19 | Exclusion for micro and small enterprises | Section 3 (online platforms) | | Whether TinyCloud qualifies |
| 20 | Internal complaint handling | Online platforms | An appeal path for removed content or suspended accounts | Only if classified as an online platform |
| 22 | Trusted flaggers | Online platforms | A flag on a notifier so their notices are handled with priority | Only if classified as an online platform |
| 23 | Measures against misuse | Online platforms | A warning and temporary suspension procedure for repeated manifestly illegal content or manifestly unfounded notices | Only if classified as an online platform |

### 8.3 Notice and action under E2EE

A notice about E2EE content can name a conversation and a message id, but TinyCloud cannot confirm what the content is. Choices to put to counsel: act on the notifier's word; require the notifier to be a member who can supply the content (the server side exists inside a community: `POST /v1/reports` accepts `evidence`, text the reporter's client chooses to disclose, stored with `evidence_unverified: true` and shown only to that community's moderators; a tinyclient feature that sends it, and any path that brings it to TinyCloud rather than to the community's moderators, are **not built**); or act on the account without the content. Of these, only acting inside a community on a member's unverified evidence is possible today.

### 8.4 Moderators and transparency

A community's own moderators are customers' users acting under the owner's rules; their actions are in the community's `audit_log` and are not TinyCloud's. Whether a community owner is itself a provider of a hosting service, with its own obligations, is a question for counsel.

### 8.5 Open items: scanning proposals and ePrivacy

| Item | State as understood | Engineering and counsel |
|---|---|---|
| The interim derogation from the ePrivacy Directive (Regulation (EU) 2021/1232) allowing voluntary detection of child sexual abuse material by interpersonal communications services | **Secondary sources only** (a search on 2026-10-31 returned commentary and advocacy sites, none official, dated up to late July 2026): it was extended to 3 April 2026, lapsed, and was reported revived with an expiry of 3 April 2028 and a carve-out for E2EE. The sources conflict on procedure | Counsel to confirm on EUR-Lex. Engineering: nothing to build while detection is voluntary. TinyCloud must be able to say plainly that it does not and cannot scan sealed content |
| The proposed permanent child-sexual-abuse regulation (procedure 2022/0155(COD)), which in earlier drafts allowed detection orders | Reportedly still under negotiation as of late July 2026 | Track the Legislative Observatory. If detection orders could reach E2EE services, the choice is between client-side scanning (which the architecture would have to host, and which breaks the E2EE claim) and refusal. That is a business and legal decision, not a coding one |
| Retention and traffic-data rules for communications services (ePrivacy Directive and national laws) | Not analysed | Counsel |
| Whether any member state requires lawful-intercept or data-retention capability from this kind of service | Not analysed | Counsel |

## 9. Sanctions screening and payments

| Topic | Engineering requirement | Question for counsel |
|---|---|---|
| **US (OFAC) and EU sanctions**: whether a hosting service must screen customers and refuse sanctioned persons and territories | A way to refuse a payer or tenant from a listed person or jurisdiction; geographic blocking at the edge (Cloudflare settings can block by country; tinyserver stores no address and cannot do it itself); a record of refusals. Screening a name against lists needs a name, which conflicts with "no identity collected" | What screening is required for a service sold by anonymous payment; whether liability is strict; how to screen when the payer is not identified; EU regimes beyond OFAC |
| **Taking payment with minimal data**: card through a processor | The processor collects name, billing address and card data and screens; TinyCloud can store only a processor token, a plan and a tenant id. Choose a processor that lets the merchant avoid receiving the details | Processor terms; chargeback and retention requirements; the processor's own screening duties |
| Cryptocurrency | A payment address per invoice; no payer details collected; the transaction id as the receipt. A self-hosted invoicing system avoids a third-party processor but not blockchain analysis | Whether to screen addresses against sanction lists; what a received payment from a listed address obliges; any money-transmission question. Not analysed |
| Cash by mail | No processor; no data beyond what the sender writes; manual handling | Whether a service that cannot screen payers may accept it; cash handling and tax records |
| **What minimal-data payment does and does not avoid** | It avoids TinyCloud *storing* payer identity. It does **not** by itself decide whether sanctions screening, tax collection or record-keeping duties apply. It can make compliance harder to demonstrate | Entirely counsel's question |
| **Tax**: sales tax and EU VAT on digital services | Consumer VAT rules are understood to require evidence of the customer's location, which is data collected for a legal duty. A tax advisor must say what evidence is needed and whether an address collected for that purpose is kept | Tax counsel |
| Separation from community membership | Payer records in a separate system, never keyed by a member identifier ([`authentication.md`](authentication.md) section 9) | |

## 10. Data residency

| Option | What stays in the region | What does not | Notes |
|---|---|---|---|
| One region per tenant, chosen at sign-up | The host: Postgres, uploads, Pocket ID, backups, the SFU and the media path (clients connect straight to the host) | The HTTP and WebSocket path: Cloudflare terminates TLS at its own edge, and where it processes is Cloudflare's. Whether Cloudflare offers regional processing for tunnels on the plans used was **not verified**. Support staff access from another region. Cloudflare Realtime TURN, if relay mode is built, is a global network | Residency of *stored* data is achievable by choosing the host's region. Residency of *processed* HTTP traffic is not under the application's control |
| Data in backups | Same region as the tenant, if the operator writes the file there | | `operator.sh backup --out FILE` writes wherever it is told; nothing records or enforces a region |
| Pocket ID | In the tenant stack, so in region | An external IdP such as Google is outside the region by definition | |
| Payer data | Wherever the billing system is | | Separate decision |

**Engineering requirements:** a `region` attribute on a tenant; deploy, backup and restore in that region; no cross-region replication by default; a list of what leaves the region. **Questions for counsel:** which transfer mechanism covers traffic that passes through Cloudflare outside the Union; whether a contractual commitment to residency can be given at all given that path; government-access exposure in the host's jurisdiction.

## 11. Summary

| Area | Built | Missing engineering | Counsel |
|---|---|---|---|
| Reports and notices (CSAM, copyright, DSA) | Kick, ban, timeout, delete channel, audit log; in-community reports with triage, retention and an owner's hold (`0015`); community suspension and the operator's hold (`0016`) | TinyCloud-level and third-party intake, preservation of reported content, disable-and-retain for one item, decision records and statements of reasons, escalation | Provider status, knowledge standard, E2EE, whether in-community moderators' knowledge is the host's |
| Valid process | Metadata inventory; per-tenant scoping (`tenant.sh`, `isolation.sh`); tenant hold; encrypted per-tenant backup and export | Intake, disclosure ledger, a per-account hold, a 90-day clock | ECS or RCS, log classification, notice |
| CALEA | n/a | Factual memo | Applicability |
| GDPR | Account deletion, rectification, minimal data, community export to its owner, a destroyable per-tenant backup key | Per-person export, erasure of the IdP account, deletion replay after restore, breach detection, DPA inputs | Roles, bases, DPIA, representative |
| DSA | | Contacts, notice form, statements of reasons, transparency counters | Classification and exemptions |
| Sanctions and payment | n/a | Payer separation, edge geoblocking | Screening, tax, processors |
| Residency | Per-tenant stacks | Region attribute, a recorded and enforced backup location | Transfers through Cloudflare |
| Pending EU scanning rules | Specified: server must not claim to scan sealed files | Watching | Positioning |
