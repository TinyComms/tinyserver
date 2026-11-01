# Performance and cost analysis

What the privacy design costs in CPU, memory, bandwidth, storage and latency, where the cost comes from, and what is not yet measured. **This file contains no measured numbers except the few hand measurements already in `docs/calls.md`, quoted with their caveats.** Every other number is arithmetic from a stated parameter, labelled as such. The measured values are to be filled in by a benchmarking pass into [`benchmarks.md`](benchmarks.md) (referenced by [`../e2ee-text.md`](../e2ee-text.md) section 10; it does not exist yet) and into the TODO tables below.

Status words are in [`README.md`](README.md). Text and attachment E2EE: the server side is implemented (#23). Its costs here are derived from the design, except the sizes tinyclient measured, which [`../e2ee-text.md`](../e2ee-text.md) section 10 quotes; server CPU and latency were not measured.

## 1. What is measured today

| Measurement | Value | Source and caveat |
|---|---|---|
| SFU CPU while idle | "no measurable CPU" | `docs/calls.md`: one hand measurement, Apple M-series laptop, release build |
| SFU CPU under a flood of STUN and RTP from 8 unknown sources on loopback | About 72% of one core at 174,000 packets a second | Same: hand measured once, not in a test; "nearly all of it receiving and dropping at the per-source budget" |
| TWCC estimate climbing from 1,000 kb/s to the high camera layer | About 250 ms on an idle laptop, loopback; not at all with every core busy | `docs/calls.md`, ignored test run by hand |
| Everything else (REST latency, fan-out latency, Postgres size, memory per socket, MLS cost, attachment throughput, per-tenant resource use) | **Not measured** | |

## 2. Where cost comes from

### 2.1 Per tenant, fixed

The compose file starts, per community: Postgres, tinyserver, Pocket ID, clamd, cloudflared, and three one-shot containers (`tinyserver-init`, `tinyserver-uploads`, `pocket-id-data`). The **limits** (ceilings the containers are killed at, not usage) are:

| Container | Memory limit | Other |
|---|---|---|
| tinyserver | 1 GB (`TINYSERVER_MEM_LIMIT`) | 2 CPUs, 512 pids |
| Postgres | 1 GB (`TINYSERVER_PG_MEM_LIMIT`) | 256 pids |
| clamd | 3 GB (`TINYSERVER_CLAMD_MEM_LIMIT`) | 128 pids. The compose comment says the signature set is "about 1.5 GiB loaded" |
| Pocket ID | 256 MB | |
| cloudflared | 256 MB | |
| `tinyserver-init` (transient) | 256 MB | |

The long-running limits sum to about 5.5 GiB. Actual resident use was not measured. The point for a hosting plan from about $10 a month: **clamd alone is the largest single memory line per tenant**, and it exists to scan plaintext uploads. Sealed uploads (#23) are not scanned, but plaintext uploads, and every community that does not use E2EE, still need it. [`tenancy.md`](tenancy.md) does not share a scanner across tenants (a shared service is shared plaintext). Instead `deploy/scan-off.yml`, or `tenant.sh new --scan none`, runs a community with no clamd (`TINYSERVER_SCAN_ENGINE=none`): every upload is marked clean unscanned and the server warns at start. That removes the largest memory line but lets any plaintext file through, so it is meant only where attachments are sealed, which is not on main yet. Not measured.

### 2.2 Per active member

| Cost | Parameter |
|---|---|
| One live socket per device, up to three per person, 1,024 per server | `docs/calls.md`. Memory per socket not measured |
| Outbox fan-out: every durable event is filtered per socket | One dispatcher task; a socket that falls 1,024 events behind is closed with `resync` |
| Writes: each message is a `messages` row and an `outbox` row (full message JSON, kept 24 hours) | Write amplification of about two rows per message plus index updates. Not measured |
| Sign-in: one pending row and one code row, a few round trips to Pocket ID | Not measured |

### 2.3 Text E2EE

| Effect | Reasoning | Status |
|---|---|---|
| Application messages cost the server no cryptography; it stores the ciphertext | `e2ee-text.md` section 10; the post route parses the MLS framing only to check the authenticated data | Implemented. Not measured |
| The server parses public handshake messages (key packages, commits) and verifies an uploaded ratchet tree (one ECDSA verification a leaf) | CPU per commit grows with the group; not measured | Implemented. Not measured |
| Commit size depends on how the tree grew: in a 1,000 device group grown by joins a Remove is 117 KB and a Welcome with the tree inside 277 KB (tinyclient's measurement, quoted in `e2ee-text.md` section 10). The server accepts commits up to 4 MiB, serves the tree apart from the Welcome, caps a group at 2,000 devices by default and shrinks Adds per commit as the group grows | Measured by the client, not here | Implemented; sizes measured by the client only |
| The group is made of **devices**, not people: every active device of every user who can view the conversation | A channel with 200 members who each have 2 devices is a 400 leaf group. Each member change is a commit with an Add per new device and a Welcome per new device | Derived |
| **Key package consumption** | Joining a community puts the new device into every encrypted channel it can view. One key package is claimed per group joined. Up to 50 packages are uploaded at a time and the server falls back to a `last_resort` package when the pool is empty. A community with more than 50 encrypted channels exhausts a fresh device's pool on its first sync | Derived from `e2ee-text.md` sections 4 and 5. Consequence for the last-resort package's reuse is a cryptographic question for review |
| **Commit latency** | A Remove or Add is not effective until some member device commits. If no member is online it waits; clients commit pending removals before they send | Specified. Time to effect not measured |
| **Ciphertext size** | A plaintext message is limited to 4000 characters; the MLS plaintext envelope to 16 KiB; the encrypted size adds the MLS framing and AEAD tag. The server accepts at most 32 KiB of ciphertext (`messages.ciphertext`, `0022`) | Limit set; overhead not measured |
| Server-side cost that disappears | The 200 character `last_message` preview of an encrypted channel is empty; no server-side search | Implemented |

### 2.4 Attachments

| Effect | Reasoning |
|---|---|
| Overhead of the sealed format | The STREAM construction adds one AEAD tag per chunk. With 64 KiB chunks (log2 size 16) and the standard 16 byte AES-GCM tag that is 16 / 65,536, about 0.024 percent, plus a 13 byte header (`TNYA1`, 1 byte, 7 byte nonce prefix). Arithmetic from the specification; not measured |
| Server CPU saved | No sniffing, no image decode and re-encode, no YARA, no clamd round trip for sealed files |
| Server CPU unchanged | Size checks, one write, one read per download |
| Client CPU and memory | Encrypt and decrypt as a stream, so a large file is not held in memory. Throughput not measured. Clients then sniff type and decode images with limits |
| Storage | Identical files from two senders no longer match (random key per attachment); no deduplication was in place anyway |
| Bandwidth | Unchanged by encryption. Thumbnails are not generated by the server: previews, if any, are the client's |
| Limits | The server cap (`file_max_bytes`, default 25 MiB, up to 100 MiB) applies to the blob. No quota per person or tenant exists |

### 2.5 Calls

| Effect | Reasoning |
|---|---|
| SFU CPU | It forwards packets and does no codec work. With DAVE it forwards ciphertext. No difference in forwarding work is expected; **not measured** |
| Per-frame overhead of DAVE | `docs/calls.md`: AES-128-GCM with an 8 byte tag, a nonce and a 2 byte marker (`0xFAFA`) at the end of each frame. That is at least 11 bytes (8 plus a nonce of at least 1 byte plus 2), more with DAVE's size field. Opus at the client target of 32 kb/s with 20 ms frames is about 80 bytes of payload per frame, so the overhead is at least about 14 percent of an audio frame. Arithmetic from those two statements, not measured. The SFU's per-publisher audio cap counts ciphertext bytes (`docs/calls.md`) |
| Video | The same group seals the H.264 picture in tinyclient; the overhead per frame is small against a video frame |
| Rekey on every join and leave | One MLS commit per change in a call. A 12 person room has at most 12 leaves. Not measured |
| Egress (the dominant cost) | Computed in `docs/calls.md` from nominal rates: eight people with cameras on, everyone connected and not deafened, each listener gets 7 audio streams at 50 kb/s and one 1,200 kb/s picture, 1.55 Mb/s each, 12.4 Mb/s in all; audio only is 8 times 7 times 50 kb/s, 2.8 Mb/s; one person sharing adds up to 21.5 Mb/s. **Plans, not measurements** |
| Relay mode | **Not implemented.** The design budgets 8 GB an hour for a six-person camera call and under 1 GB an hour for audio only, at $0.05 per GB after 1,000 GB a month (figures from `docs/calls.md`, quoting Cloudflare's documentation, not re-checked) |

### 2.6 Cost drivers for a managed service

None of these is measured. Each one needs a number before a price makes sense.

| Driver | Where it is bounded today |
|---|---|
| Media egress on the host's link | Per-publisher caps, an optional `TINYSERVER_MEDIA_EGRESS_KBPS` plan, room and server caps (12 per room, 32 per server). No per-tenant accounting |
| Storage | Per-file caps only. No quota |
| Database size | No quota. Messages are retained until deleted |
| Cloudflare tunnel traffic | Not bounded, not measured. Cloudflare's terms for the plan used were not reviewed |
| Memory per tenant | Compose limits (section 2.1); actual use unknown |
| Request rate | No limit outside sign-in and per-socket frames |
| Support, abuse handling, legal process | Not an infrastructure cost; see [`abuse-response.md`](abuse-response.md) and [`compliance.md`](compliance.md) |

## 3. TODO: measurements to take

Everything in the "Result" column is **TODO, not measured**. Each row needs: the commit, the hardware, the build profile, the method, the date, and the raw data in [`benchmarks.md`](benchmarks.md). Do not copy numbers from other systems.

| # | Metric | Method | Compare | Result |
|---|---|---|---|---|
| P1 | Idle resident memory of each container (tinyserver, Postgres, Pocket ID, clamd, cloudflared) after a 24 hour idle run | `docker stats` sampled | One tenant stack | TODO |
| P2 | Resident memory with 50, 200, 1,000 live sockets | Load tool opening authenticated sockets | Same stack | TODO |
| P3 | `POST /v1/conversations/{id}/messages` latency (p50, p95, p99) and throughput at 1, 10, 100 concurrent senders | Load tool, plaintext | Plaintext vs encrypted (when merged) | TODO |
| P4 | Fan-out latency: POST to `message.created` frame received, at 10, 100, 1,000 connected members | Instrumented clients | Plaintext vs encrypted | TODO |
| P5 | Outbox rows per second sustained before the dispatcher or sockets lag (`resync` count) | Load tool | | TODO |
| P6 | Postgres size per 1 million messages (plaintext 100 characters; ciphertext of the same text), including outbox | `pg_total_relation_size` | Plaintext vs encrypted | TODO |
| P7 | Ciphertext size for 1, 100, 1,000, 4,000 characters, and the maximum accepted | Client library | | TODO |
| P8 | MLS: commit size, commit creation and processing time, Welcome size, for groups of 3, 20, 100, 400, 1,000 devices | Client library (`crates/e2ee` of tinyclient) and server validation | Add one device; remove one device; add 20 | TODO |
| P9 | Server CPU per handshake message validated | Profiler under P8 load | | TODO |
| P10 | Key packages consumed when a new device joins a community with 10, 50, 200 encrypted channels; behaviour when the pool is exhausted | Test harness | | TODO |
| P11 | Time from a pending Remove to its commit when members are online, and when none are | Test harness | | TODO |
| P12 | Attachment upload: throughput and server CPU for 1 MiB, 25 MiB, 100 MiB, plaintext (with scan) vs sealed | Load tool | | TODO |
| P13 | Client encrypt and decrypt throughput and peak memory for 25 MiB and 100 MiB | Client benchmark | | TODO |
| P14 | SFU CPU per participant: audio only, camera, share; with and without DAVE | Headless client (`crates/sfu/src/client.rs`) | | TODO |
| P15 | Bandwidth overhead of DAVE on a real Opus stream at 32 kb/s | Packet capture | Computed value in section 2.5 | TODO |
| P16 | DAVE seal and open latency added on the client | `mediad` benchmark | | TODO |
| P17 | Time to run `migrate` on databases of 1 million and 10 million messages | Test database | | TODO |
| P18 | Backup size and time for a tenant at P6 sizes | `deploy/tenant/operator.sh backup`; the staging tmpfs defaults to 4g (`TINYSERVER_BACKUP_TMPFS`); whether that bounds a large tenant was not checked | | TODO |
| P19 | Smallest memory and CPU allotment per tenant that holds a 50 member community without limit kills | Soak test | | TODO |
| P20 | Cost model: a table of per-tenant monthly cost for egress, storage, memory and tunnel at three community sizes | Compute from P1 to P19 and the provider's prices | | TODO |

## 4. Trade-offs the E2EE design accepts for privacy

| Feature | Plaintext community | Encrypted conversation |
|---|---|---|
| Server-side search | Not implemented anyway | Cannot exist |
| Link previews and thumbnails made by the server | None implemented | Cannot exist |
| Virus and type scanning of uploads | clamd and YARA, before the message can reference the file | None for sealed files; the client protects itself |
| Moderator removal of a message | `manage_channels` deletes the channel; no per-message moderator delete exists today either | None in v1 |
| History for new members | Yes, whatever permissions allow | No. A new device reads nothing from before it joined |
| Server-side retention policies | None implemented | Same |
| Large communities | Bounded by sockets and CPU | Bounded by MLS group size and commit latency; "large communities should use channels with a bounded device count" (`e2ee-text.md` section 10) |
